// DL_manager_replace.ipp
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <iostream>
#include <iomanip>
#include <dirent.h>
#include <cctype>
#include <fstream>
#include <sstream>
#include <set>
#include <algorithm>
#include "daemon.hpp"

// Constants
static const size_t REMOTE_MEM_SIZE = 4096;
static const size_t SHELLCODE_PATH_OFFSET = 256;
static const size_t SHELLCODE_RESULT_OFFSET = 512;
static const time_t MTIME_TOLERANCE = 1;

//=============================================================================
// Static helper functions 
//=============================================================================

static void log_replacement_start(const std::string& target, const std::string& new_lib, const std::string& function) {
    LOG_RESULT("=== Starting library replacement ===");
    LOG_RESULT("Target pattern: %s", target.c_str());
    LOG_RESULT("New: %s", new_lib.c_str());
    LOG_RESULT("Function: %s", function.c_str());
}

static void log_replacement_result(bool success) {
    if (success) {
        LOG_RESULT("=== Library replacement completed successfully ===");
    } else {
        LOG_RESULT("=== Library replacement failed ===");
    }
}

static bool check_required_addresses(uintptr_t dlopen_addr, uintptr_t dlclose_addr, uintptr_t syscall_insn) {
    if (dlopen_addr == 0 || dlclose_addr == 0 || syscall_insn == 0) {
        LOG_ERR("Required addresses not initialized");
        return false;
    }
    return true;
}

// Update file info in tracker if it changed on disk (with tolerance for mtime)
// Update file info in tracker if it changed on disk (with tolerance for mtime)
static void update_tracked_file_info(TrackedLibrary& lib, time_t mtime, size_t size, bool info_ok) {
    if (!info_ok) {
        LOG_DBG("update_tracked_file_info: no valid info, skipping");
        return;
    }
    
    LOG_DBG("update_tracked_file_info: lib.mtime=%ld, lib.size=%zu, new.mtime=%ld, new.size=%zu",
            lib.mtime, lib.file_size, mtime, size);
    
    // If we don't have valid info in tracker yet, just store it
    if (lib.file_size == 0 && lib.mtime == 0) {
        LOG_DBG("First time getting valid file info for tracked library - storing");
        lib.mtime = mtime;
        lib.file_size = size;
        return;
    }
    
    // Normal case - compare with existing
    bool changed = false;
    
    // Size change is definitive
    if (lib.file_size != size) {
        LOG_DBG("Size changed: %zu -> %zu", lib.file_size, size);
        changed = true;
    }
    // For mtime, only consider significant changes (> tolerance)
    else if (lib.mtime != mtime) {
        time_t diff = llabs(lib.mtime - mtime);
        if (diff > MTIME_TOLERANCE) {
            LOG_DBG("mtime changed significantly: %ld -> %ld (diff=%ld > %ld)", 
                    lib.mtime, mtime, diff, MTIME_TOLERANCE);
            changed = true;
        } else {
            LOG_DBG("mtime changed insignificantly (diff=%ld <= %ld) - ignoring", 
                    diff, MTIME_TOLERANCE);
        }
    }
    
    if (changed) {
        LOG_WARN("Library file has changed on disk since last load");
        lib.mtime = mtime;
        lib.file_size = size;
    } else {
        LOG_DBG("File unchanged");
    }
}

// Start cleanup daemon on first successful patch
static void ensure_daemon_running() {
    static bool daemon_started = false;
    if (!daemon_started) {
        if (!Daemon::is_running()) {
            Daemon::start();
        }
        daemon_started = true;
    }
}
static bool stop_all_threads(const std::vector<pid_t>& tids, std::vector<ThreadContext>& contexts) {
    contexts.clear();
    for (pid_t tid : tids) {
        if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == -1) {
            LOG_ERR("ptrace ATTACH failed for thread %d", tid);
            for (const auto& ctx : contexts) {
                ptrace(PTRACE_DETACH, ctx.tid, nullptr, nullptr);
            }
            return false;
        }
        int status;
        waitpid(tid, &status, 0);
        if (!WIFSTOPPED(status)) {
            LOG_ERR("Thread %d did not stop after attach", tid);
            for (const auto& ctx : contexts) {
                ptrace(PTRACE_DETACH, ctx.tid, nullptr, nullptr);
            }
            return false;
        }
        ThreadContext ctx;
        ctx.tid = tid;
        if (ptrace(PTRACE_GETREGS, tid, nullptr, &ctx.regs) == -1) {
            LOG_ERR("ptrace GETREGS failed for thread %d", tid);
            ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
            for (const auto& c : contexts) {
                ptrace(PTRACE_DETACH, c.tid, nullptr, nullptr);
            }
            return false;
        }
        contexts.push_back(ctx);
    }
    return true;
}

static bool all_threads_outside(const std::vector<ThreadContext>& contexts,
                                const std::vector<std::pair<uintptr_t, uintptr_t>>& segments) {
    for (const auto& ctx : contexts) {
        if (address_in_library(Arch::get_ip(ctx.regs), segments)) {
            return false;
        }
    }
    return true;
}

static void restore_and_detach_all(const std::vector<ThreadContext>& contexts) {
    for (const auto& ctx : contexts) {
        ptrace(PTRACE_SETREGS, ctx.tid, nullptr, &ctx.regs);
        ptrace(PTRACE_DETACH, ctx.tid, nullptr, nullptr);
    }
}

static std::vector<pid_t> get_all_threads(pid_t pid) {
    std::vector<pid_t> tids;
    std::string task_path = "/proc/" + std::to_string(pid) + "/task/";

    DIR* dir = opendir(task_path.c_str());
    if (!dir) return tids;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type == DT_DIR) {
            bool is_number = true;
            for (char* p = entry->d_name; *p; ++p) {
                if (!isdigit(*p)) { is_number = false; break; }
            }
            if (is_number) tids.push_back(atoi(entry->d_name));
        }
    }
    closedir(dir);

    std::sort(tids.begin(), tids.end());
    return tids;
}

static bool write_remote_memory(pid_t pid, uintptr_t addr, const void* data, size_t size) {
    // Cast data to byte array for easy manipulation
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    
    // Calculate word-aligned range that covers our memory region
    // ptrace POKEDATA works with whole words (8 bytes), so we need to handle partial words
    uintptr_t start_word = addr & ~(sizeof(long) - 1);  // First word boundary
    uintptr_t end_word = (addr + size + sizeof(long) - 1) & ~(sizeof(long) - 1);  // Last word boundary
    
    LOG_DBG("Writing %zu bytes to 0x%lx, word range 0x%lx-0x%lx", 
            size, addr, start_word, end_word);

    // Iterate over each affected word
    for (uintptr_t w = start_word; w < end_word; w += sizeof(long)) {
        long word = 0;
        bool need_read = false;
        
        // Check if this word is partially outside our target range
        // If word starts before addr OR ends after addr+size, we need to preserve existing data
        if (w < addr || w + sizeof(long) > addr + size) {
            need_read = true;
        }
        
        if (need_read) {
            errno = 0;
            // Read the current word value from remote process
            word = ptrace(PTRACE_PEEKDATA, pid, w, nullptr);
            if (word == -1 && errno != 0) {
                LOG_ERR("ptrace PEEKDATA failed at 0x%lx: %s", w, strerror(errno));
                return false;
            }
            LOG_DBG("Read word at 0x%lx: 0x%016lx", w, word);
        }
        
        // Calculate offsets for merging new data into the word
        // src_offset: where in 'bytes' to start copying
        // dst_offset: where in the word to place the data
        // copy_len: how many bytes to copy
        
        size_t src_offset = (w > addr) ? 0 : (addr - w);
        // If word starts before addr, skip bytes before addr
        // Example: addr=0x1003, w=0x1000 → src_offset = 3
        
        size_t dst_offset = (w < addr) ? (addr - w) : 0;
        // If word starts before addr, we start writing at offset (addr-w) in the word
        
        size_t copy_len = std::min(sizeof(long) - dst_offset, 
                                   size - (w - addr + dst_offset));
        // Copy until we hit word boundary or run out of data
        
        LOG_DBG("Word 0x%lx: dst_offset=%zu, src_offset=%zu, copy_len=%zu", 
                w, dst_offset, src_offset, copy_len);
        
        // Merge new bytes into the word
        memcpy(reinterpret_cast<uint8_t*>(&word) + dst_offset, 
               bytes + src_offset + (w - addr), copy_len);
        
        LOG_DBG("Writing word at 0x%lx: 0x%016lx", w, word);
        
        // Write the modified word back to remote process
        if (ptrace(PTRACE_POKEDATA, pid, w, word) == -1) {
            LOG_ERR("ptrace POKEDATA failed at 0x%lx: %s", w, strerror(errno));
            return false;
        }
        
#ifdef DEBUG
        // Verification step - read back and compare
        long verify = ptrace(PTRACE_PEEKDATA, pid, w, nullptr);
        if (verify == -1 && errno != 0) {
            LOG_ERR("Verification read failed at 0x%lx", w);
            return false;
        }
        if (verify != word) {
            LOG_ERR("Verification failed at 0x%lx: wrote 0x%016lx, read 0x%016lx", 
                    w, word, verify);
            return false;
        }
#endif
    }
    
    LOG_DBG("Successfully wrote %zu bytes to 0x%lx", size, addr);
    return true;
}

static bool read_remote_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size) {
    // iovec structures for scatter-gather I/O
    struct iovec local = {buffer, size};     // Local buffer to read into
    struct iovec remote = {reinterpret_cast<void*>(addr), size};  // Remote memory region
    
    // process_vm_readv - Linux syscall for efficient cross-process memory reading
    // It reads 'size' bytes from remote process at 'addr' directly into local buffer
    // Parameters: pid, local iovec array (1 element), remote iovec array (1 element), flags=0
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    
    // Return true only if we read exactly the requested number of bytes
    return n == static_cast<ssize_t>(size);
}

bool DL_Manager::read_remote_memory_raw(uintptr_t addr, void* buffer, size_t size) const {
    return read_remote_memory(pid_, addr, buffer, size);
}

static uintptr_t remote_mmap(pid_t pid, size_t length, int prot, int flags, int fd, off_t offset,
                             uintptr_t syscall_insn_addr) {
    uintptr_t result;
    if (!Arch::remote_syscall(pid, result, Arch::SYS_MMAP, 
    0,        // arg1 (rdi): addr - 0 = let kernel choose
    length,   // arg2 (rsi): size
    prot,     // arg3 (rdx): protection flags
    flags,    // arg4 (r10): mapping flags
    fd,       // arg5 (r8):  file descriptor
    offset,   // arg6 (r9):  file offset
    syscall_insn_addr)) {
        return 0;
    }

    return result;
}

static bool remote_munmap(pid_t pid, uintptr_t addr, size_t length, uintptr_t syscall_insn_addr) {
    uintptr_t result;
    if (!Arch::remote_syscall(pid, result, Arch::SYS_MUNMAP,
        addr,     // arg1 (rdi): address to unmap
        length,   // arg2 (rsi): size to unmap
        0,        // arg3 (rdx): unused
        0,        // arg4 (r10): unused
        0,        // arg5 (r8):  unused
        0,        // arg6 (r9):  unused
        syscall_insn_addr)) {
        return false;
    }

    return result == 0;
}

// ============================================================================
// DL_Manager implementation
// ============================================================================

void DL_Manager::init_addresses() {
    LibraryInfo libc_info = get_library_info("libc.so");
    if (libc_info.base_addr == 0) {
        LOG_ERR("Failed to find libc.so in target process - required for dlopen/dlclose");
        return;
    }
    
    dlopen_addr_ = get_symbol_address(libc_info.base_addr, "dlopen");
    dlclose_addr_ = get_symbol_address(libc_info.base_addr, "dlclose");
    syscall_insn_ = find_syscall_instruction(libc_info.base_addr);
    
    if (dlopen_addr_ == 0 || dlclose_addr_ == 0 || syscall_insn_ == 0) {
        LOG_ERR("Failed to locate required symbols in libc");
        return;
    }
    
    LOG_DBG("Initialized addresses: dlopen=0x%lx, dlclose=0x%lx, syscall=0x%lx",
            dlopen_addr_, dlclose_addr_, syscall_insn_);
}

uintptr_t DL_Manager::find_syscall_instruction(uintptr_t libc_base) {
    return Arch::find_syscall_instruction(this, libc_base);
}

// Check if library is already loaded in target process
// Returns:
// - true with base_addr/handle filled if found in tracker or /proc/pid/maps
// - false if not found (library needs to be loaded)
bool DL_Manager::is_library_already_loaded(const std::string& lib_path, uintptr_t& base_addr, uintptr_t& handle) {
    // Normalize path for tracker lookup
    std::string normalized = normalize_path(lib_path);
    
    // First check our tracker (libraries we loaded ourselves)
    auto it = tracked_libraries_.find(normalized);
    if (it != tracked_libraries_.end()) {
        base_addr = it->second.base_addr;
        handle = it->second.handle;
        return true;
    }
    
    // If not in tracker, check /proc/pid/maps (using original path for string search)
    std::string maps_path = "/proc/" + std::to_string(pid_) + "/maps";
    std::ifstream maps_file(maps_path);
    if (!maps_file.is_open()) return false;
    
    std::string line;
    while (std::getline(maps_file, line)) {
        if (line.find(lib_path) != std::string::npos) {
            size_t dash = line.find('-');
            if (dash != std::string::npos) {
                base_addr = std::stoul(line.substr(0, dash), nullptr, 16);
                handle = 0;
                return true;
            }
        }
    }
    return false;
}

bool DL_Manager::is_library_active(const std::string& lib_path) const {
    auto it = tracked_libraries_.find(lib_path);
    if (it == tracked_libraries_.end()) {
        return false;
    }
    return it->second.is_active;
}

bool DL_Manager::test_syscall(pid_t tid) {
    if (syscall_insn_ == 0) return false;
    
    uintptr_t result;
    // Arch::remote_syscall parameters:
    // 1. tid               - thread to execute syscall in
    // 2. result (output)   - will contain syscall return value
    // 3. Arch::SYS_GETPID  - syscall number (39 on x86_64)
    // 4. arg1 (0)          - SYS_GETPID has no arguments, so all are 0
    // 5. arg2 (0)          
    // 6. arg3 (0)          
    // 7. arg4 (0)          
    // 8. arg5 (0)          
    // 9. arg6 (0)          
    // 10. syscall_insn_    - address of "syscall" instruction in remote process
    if (!Arch::remote_syscall(tid, result, Arch::SYS_GETPID, 0, 0, 0, 0, 0, 0, syscall_insn_))
        return false;
    
    return true;
}

bool DL_Manager::prepare_thread_for_injection(pid_t tid, struct user_regs_struct& prepared_regs) {
    LOG_DBG("Preparing thread %d for injection", tid);

    // Execute two PTRACE_SYSCALL steps to ensure thread is out of any syscall
    // Reason: If thread is inside a syscall when we try to execute shellcode,
    // the kernel will restart the syscall after we detach, corrupting program state
    // First PTRACE_SYSCALL: 
    //   - If thread was in syscall, it will exit it and stop on syscall exit
    //   - If thread was not in syscall, it will enter next syscall and stop on entry
    // Second PTRACE_SYSCALL:
    //   - Ensures thread is stopped at a safe point (not inside any syscall)
    for (int i = 0; i < 2; ++i) {
        if (ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr) == -1) {
            LOG_ERR("ptrace SYSCALL failed during preparation (attempt %d)", i);
            return false;
        }
        
        int status;
        waitpid(tid, &status, 0);
        
        if (!WIFSTOPPED(status)) {
            LOG_ERR("Thread did not stop after PTRACE_SYSCALL (attempt %d)", i);
            return false;
        }
        
        int sig = WSTOPSIG(status);
        if (sig != SIGTRAP) {
            LOG_DBG("Thread stopped with signal %d (expected SIGTRAP)", sig);
        }
    }
    
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &prepared_regs) == -1) {
        LOG_ERR("Failed to get registers after preparation");
        return false;
    }
    
    LOG_DBG("Thread prepared: IP=0x%llx, SP=0x%llx", 
            (unsigned long long)Arch::get_ip(prepared_regs),
            (unsigned long long)Arch::get_sp(prepared_regs));
    
    return true;
}

std::vector<pid_t> DL_Manager::stop_threads_and_prepare_main(pid_t& main_tid, 
                                                              struct user_regs_struct& saved_regs) {
    std::vector<pid_t> tids = get_all_threads(pid_);
    if (tids.empty()) {
        LOG_ERR("No threads found - process may have terminated");
        return {};
    }
    
    std::vector<ThreadContext> contexts;
    if (!stop_all_threads(tids, contexts)) {
        LOG_ERR("Failed to stop all threads");
        return {};
    }
    
    // Find main thread and save its original registers
    main_tid = pid_;
    bool found = false;
    for (const auto& ctx : contexts) {
        if (ctx.tid == main_tid) {
            saved_regs = ctx.regs;
            found = true;
            break;
        }
    }
    
    if (!found) {
        LOG_ERR("Main thread not found in stopped threads");
        restore_and_detach_all(contexts);
        return {};
    }
    
    // Prepare main thread for injection 
    struct user_regs_struct prepared_regs;
    if (!prepare_thread_for_injection(main_tid, prepared_regs)) {
        restore_and_detach_all(contexts);
        return {};
    }
    
    // Update saved_regs with prepared state
    saved_regs = prepared_regs;
    
    // Return all stopped thread IDs
    std::vector<pid_t> stopped_tids;
    for (const auto& ctx : contexts) {
        stopped_tids.push_back(ctx.tid);
    }
    return stopped_tids;
}

uintptr_t DL_Manager::allocate_remote_memory(pid_t tid, size_t size) {
    return remote_mmap(tid, size,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0,
                       syscall_insn_);
}

bool DL_Manager::write_shellcode(pid_t tid, uintptr_t shellcode_addr,
                                                   uintptr_t path_addr, uintptr_t result_addr) {
    auto shellcode = Arch::generate_dlopen_shellcode(path_addr, dlopen_addr_, result_addr);
    
    // Debug: dump shellcode bytes before writing
    LOG_DBG("Shellcode size: %zu bytes", shellcode.size());
    LOG_DBG("Shellcode before writing:");
    for (size_t i = 0; i < shellcode.size(); i += 8) {
        size_t chunk = std::min(shellcode.size() - i, size_t(8));
        uint64_t val = 0;
        memcpy(&val, &shellcode[i], chunk);
        LOG_DBG("  offset %3zu: 0x%016lx", i, val);
    }
    
#ifdef DEBUG
    // In debug builds, verify that result_addr is writable
    // by writing a test pattern and reading it back
    LOG_DBG("Testing writability of result_addr 0x%lx", result_addr);
    uint64_t test_val = 0xDEADBEEFDEADBEEF;
    if (!write_remote_memory(tid, result_addr, &test_val, sizeof(test_val))) {
        LOG_ERR("result_addr is not writable!");
        return false;
    }
    uint64_t verify_val = 0;
    if (!read_remote_memory(tid, result_addr, &verify_val, sizeof(verify_val)) || 
        verify_val != test_val) {
        LOG_ERR("result_addr verification failed!");
        return false;
    }
    // Clear test pattern
    test_val = 0;
    write_remote_memory(tid, result_addr, &test_val, sizeof(test_val));
    LOG_DBG("result_addr is writable");
#else
    // Release builds: skip verification, assume it's writable
    // (we allocated it with PROT_WRITE via remote_mmap)
    (void)result_addr; // Suppress unused parameter warning
#endif
    
    // Write the actual shellcode
    if (!write_remote_memory(tid, shellcode_addr, shellcode.data(), shellcode.size()))
        return false;
    
#ifdef DEBUG
    // Verify shellcode was written correctly by reading it back
    std::vector<uint8_t> verify(shellcode.size());
    if (!read_remote_memory(tid, shellcode_addr, verify.data(), verify.size()))
        return false;
    if (memcmp(verify.data(), shellcode.data(), shellcode.size()) != 0)
        return false;
    LOG_DBG("Shellcode written and verified successfully");
#else
    // Release builds: trust that write succeeded
    LOG_DBG("Shellcode written successfully");
#endif
    
    return true;
}

bool DL_Manager::execute_shellcode_and_get_handle(pid_t tid, uintptr_t shellcode_addr,
                                                   struct user_regs_struct& saved_regs,
                                                   uintptr_t& out_handle) {
    // Create new register state with IP pointing to shellcode
    struct user_regs_struct new_regs = saved_regs;
    Arch::set_ip(new_regs, shellcode_addr);
    
    LOG_DBG("Setting IP to 0x%lx, original SP=0x%lx", shellcode_addr, Arch::get_sp(saved_regs));
    
    // Apply new register state to remote thread
    if (ptrace(PTRACE_SETREGS, tid, nullptr, &new_regs) == -1) {
        LOG_ERR("ptrace SETREGS failed: %s", strerror(errno));
        return false;
    }
    
    // Let the thread execute the shellcode
    if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) == -1) {
        LOG_ERR("ptrace CONT failed: %s", strerror(errno));
        return false;
    }
    
    // Wait for shellcode to hit int3 and stop
    int status;
    waitpid(tid, &status, 0);
    
    uintptr_t handle = 0;
    uintptr_t result_addr = shellcode_addr + SHELLCODE_RESULT_OFFSET;
    
    if (WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);
        LOG_DBG("Thread stopped with signal %d", sig);
        
        if (sig == SIGTRAP) {
            // Shellcode completed successfully, read the handle
            LOG_DBG("Got SIGTRAP, reading dlopen result");
            if (read_remote_memory(tid, result_addr, &handle, sizeof(handle))) {
                LOG_DBG("dlopen returned handle 0x%lx", handle);
                if (handle != 0) {
                    out_handle = handle;
                    
                    // Restore original registers
                    if (ptrace(PTRACE_SETREGS, tid, nullptr, &saved_regs) == -1) {
                        LOG_ERR("Failed to restore registers after shellcode: %s", strerror(errno));
                    }
                    
                    return true;
                } else {
                    LOG_ERR("dlopen returned NULL handle");
                }
            } else {
                LOG_ERR("Failed to read handle from result_addr");
            }
        } else if (sig == SIGSEGV) {
            // Shellcode crashed - dump debug info
            LOG_ERR("Segmentation fault in shellcode");
            
            siginfo_t siginfo;
            if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, &siginfo) == 0) {
                LOG_ERR("Fault address: 0x%lx, code: %d", 
                        (uintptr_t)siginfo.si_addr, siginfo.si_code);
            }
            
            Arch::dump_registers(tid, this);
        } else {
            LOG_ERR("Unexpected signal %d after shellcode", sig);
        }
    } else if (WIFEXITED(status)) {
        LOG_ERR("Thread exited with status %d", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        LOG_ERR("Thread terminated with signal %d", WTERMSIG(status));
    } else {
        LOG_ERR("Unexpected wait status %d", status);
    }
    
    // Restore original registers on any failure
    LOG_INFO("Restoring original registers after error");
    if (ptrace(PTRACE_SETREGS, tid, nullptr, &saved_regs) == -1) {
        LOG_ERR("Failed to restore registers after shellcode: %s", strerror(errno));
    }
    
    return false;
}

uintptr_t DL_Manager::get_loaded_library_base(const std::string& lib_path) const {
    std::string maps_path = "/proc/" + std::to_string(pid_) + "/maps";
    std::ifstream maps_file(maps_path);
    if (!maps_file.is_open()) return 0;
    
    std::string line;
    while (std::getline(maps_file, line)) {
        if (line.find(lib_path) != std::string::npos) {
            size_t dash = line.find('-');
            if (dash != std::string::npos) {
                return std::stoul(line.substr(0, dash), nullptr, 16);
            }
        }
    }
    return 0;
}

uintptr_t DL_Manager::load_new_library(pid_t tid, const std::string& lib_path,
                                        uintptr_t& out_handle,
                                        struct user_regs_struct& saved_regs) {
    if (dlopen_addr_ == 0 || syscall_insn_ == 0) {
        LOG_ERR("Required addresses not initialized");
        return 0;
    }

    LOG_INFO("Loading new library: %s", lib_path.c_str());
    LOG_DBG("dlopen_addr=0x%lx, syscall_insn=0x%lx", dlopen_addr_, syscall_insn_);

#ifdef DEBUG
    // Test remote syscall before proceeding (debug only)
    uintptr_t test_result;
    if (!Arch::remote_syscall(tid, test_result, Arch::SYS_GETPID, 0, 0, 0, 0, 0, 0, syscall_insn_)) {
        LOG_ERR("remote_syscall test failed before allocation");
        return 0;
    }
    LOG_DBG("remote_syscall test passed, result=%lu", test_result);
#endif

    // Allocate remote memory for shellcode
    uintptr_t remote_mem = allocate_remote_memory(tid, REMOTE_MEM_SIZE);
    if (remote_mem == 0) {
        LOG_ERR("Failed to allocate remote memory");
        return 0;
    }
    LOG_DBG("Remote memory allocated at 0x%lx", remote_mem);

    // Calculate addresses for path and result
    uintptr_t path_addr = remote_mem + SHELLCODE_PATH_OFFSET;
    uintptr_t result_addr = remote_mem + SHELLCODE_RESULT_OFFSET;
    
    LOG_DBG("path_addr = 0x%lx, result_addr = 0x%lx", path_addr, result_addr);

    // Write library path to remote memory
    if (!write_remote_memory(tid, path_addr, lib_path.c_str(), lib_path.size() + 1)) {
        LOG_ERR("Failed to write library path");
        remote_munmap(pid_, remote_mem, REMOTE_MEM_SIZE, syscall_insn_);
        return 0;
    }
    LOG_INFO("Library path written to remote memory");

#ifdef DEBUG
    // Verify path was written correctly (debug only)
    char path_check[256] = {0};
    if (read_remote_memory(tid, path_addr, path_check, lib_path.size() + 1)) {
        LOG_DBG("Path verification: %s", path_check);
    }
#endif

    // Write shellcode
    if (!write_shellcode(tid, remote_mem, path_addr, result_addr)) {
        LOG_ERR("Failed to write shellcode");
        remote_munmap(pid_, remote_mem, REMOTE_MEM_SIZE, syscall_insn_);
        return 0;
    }
    LOG_DBG("Shellcode written to remote memory");

    // Execute shellcode and get dlopen handle
    if (!execute_shellcode_and_get_handle(tid, remote_mem, saved_regs, out_handle)) {
        LOG_ERR("Failed to execute shellcode and get handle");
        remote_munmap(pid_, remote_mem, REMOTE_MEM_SIZE, syscall_insn_);
        return 0;
    }

    // Clean up remote memory
    LOG_DBG("Cleaning up remote memory");
    remote_munmap(pid_, remote_mem, REMOTE_MEM_SIZE, syscall_insn_);

    // Find base address of newly loaded library in /proc/pid/maps
    uintptr_t new_lib_base = get_loaded_library_base(lib_path);
    if (new_lib_base == 0) {
        LOG_ERR("Failed to find new library base in maps");
        return 0;
    }

    LOG_INFO("New library loaded: base=0x%lx, handle=0x%lx", new_lib_base, out_handle);
    return new_lib_base;
}

bool DL_Manager::unload_library_by_handle(pid_t tid, uintptr_t handle,
                                           struct user_regs_struct& saved_regs) {
    // Check that required addresses are initialized
    if (dlclose_addr_ == 0 || syscall_insn_ == 0) {
        LOG_ERR("Required addresses not initialized");
        return false;
    }
    
    // Validate handle
    if (handle == 0) {
        LOG_ERR("Invalid handle (0)");
        return false;
    }
    
    // Allocate remote memory for unload shellcode
    size_t mem_size = 4096;
    uintptr_t remote_mem = remote_mmap(tid, mem_size,
                                       PROT_READ | PROT_WRITE | PROT_EXEC,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0,
                                       syscall_insn_);
    if (remote_mem == 0) {
        LOG_ERR("Failed to allocate remote memory for unload");
        return false;
    }
    
    // Address where dlclose result will be stored
    uintptr_t result_addr = remote_mem + 256;
    
    LOG_DBG("Unloading library with handle = 0x%lx", handle);
    LOG_DBG("Shellcode at: 0x%lx", remote_mem);
    LOG_DBG("Result addr: 0x%lx", result_addr);
    LOG_DBG("dlclose addr: 0x%lx", dlclose_addr_);
    
    // Generate dlclose shellcode
    auto shellcode = Arch::generate_dlclose_shellcode(handle, dlclose_addr_, result_addr);
    
    // Clear result area before execution
    uint64_t zero = 0;
    if (!write_remote_memory(tid, result_addr, &zero, sizeof(zero))) {
        LOG_ERR("Failed to clear result area");
        remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
        return false;
    }
    
    // Write shellcode to remote memory
    if (!write_remote_memory(tid, remote_mem, shellcode.data(), shellcode.size())) {
        LOG_ERR("Failed to write unload shellcode");
        remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
        return false;
    }
    
    // Set instruction pointer to shellcode
    struct user_regs_struct new_regs = saved_regs;
    Arch::set_ip(new_regs, remote_mem);
    
    if (ptrace(PTRACE_SETREGS, tid, nullptr, &new_regs) == -1) {
        LOG_ERR("ptrace SETREGS failed: %s", strerror(errno));
        remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
        return false;
    }
    
    // Execute shellcode
    if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) == -1) {
        LOG_ERR("ptrace CONT failed: %s", strerror(errno));
        remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
        return false;
    }
    
    // Wait for shellcode to complete (should hit int3)
    int status;
    waitpid(tid, &status, 0);
    
    bool success = false;
    uint64_t dlclose_result = 0;
    
    if (WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);
        LOG_DBG("Thread stopped with signal %d", sig);
        
        if (sig == SIGTRAP) {
            // Shellcode completed successfully, read dlclose result
            if (read_remote_memory(tid, result_addr, &dlclose_result, sizeof(dlclose_result))) {
                LOG_INFO("dlclose returned %lu", dlclose_result);
                success = (dlclose_result == 0);  // dlclose returns 0 on success
            } else {
                LOG_ERR("Failed to read dlclose result");
            }
        } else {
            // Unexpected signal - dump registers for debugging
            LOG_ERR("Unexpected signal %d during unload", sig);
            Arch::dump_registers(tid, this);
        }
    } else {
        LOG_ERR("Unexpected wait status: %d", status);
    }
    
    // Restore original registers
    ptrace(PTRACE_SETREGS, tid, nullptr, &saved_regs);
    
    // Free remote memory
    remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
    
    if (success) {
        LOG_DBG("Successfully unloaded library with handle 0x%lx", handle);
    }
    
    return success;
}

void DL_Manager::print_library_tracker() const {
    LOG_INFO("=== Library Tracker Status ===");
    LOG_INFO("Tracked libraries: %zu", tracked_libraries_.size());
    
    for (const auto& pair : tracked_libraries_) {
        const TrackedLibrary& lib = pair.second;
        std::string status;
        if (lib.is_active) {
            status = "ACTIVE";
        } else if (lib.is_original) {
            status = "ORIGINAL (inactive)";
        } else {
            status = "INACTIVE (can unload)";
        }
        
        LOG_INFO("  Path: %s", lib.path.c_str());
        LOG_INFO("    Handle   : 0x%lx", lib.handle);
        LOG_INFO("    Base     : 0x%lx", lib.base_addr);
        LOG_INFO("    Status   : %s", status.c_str());
        
        if (!lib.provided_functions.empty()) {
            LOG_INFO("    Functions:");
            for (const auto& f : lib.provided_functions) {
                LOG_INFO("      - %s", f.c_str()); 
            }
        } else {
            LOG_INFO("    Functions: (none)");
        }
        
        LOG_INFO("    Patched libs: %zu", lib.patched_libraries.size());
    }
    LOG_INFO("==============================");
}

bool DL_Manager::unload_library(const std::string& lib_path) {
    // Normalize path for tracker lookup
    std::string normalized = normalize_path(lib_path);
    
    auto it = tracked_libraries_.find(normalized);
    if (it == tracked_libraries_.end()) {
        LOG_ERR("Library %s not found in tracker", lib_path.c_str());
        return false;
    }
    
    TrackedLibrary& lib = it->second;
    
    // Safety checks
    if (lib.is_active) {
        LOG_ERR("Cannot unload active library");
        return false;
    }
    if (lib.is_original) {
        LOG_ERR("Cannot unload original library");
        return false;
    }
    
    LOG_INFO("Unloading library: %s", lib_path.c_str());
    
    // Stop all threads in target process
    std::vector<pid_t> tids = get_all_threads(pid_);
    std::vector<ThreadContext> contexts;
    
    if (!stop_all_threads(tids, contexts)) {
        LOG_ERR("Failed to stop threads");
        return false;
    }
    
    // Select worker thread (main thread or first available)
    pid_t worker_tid = pid_;
    bool found = false;
    for (const auto& ctx : contexts) {
        if (ctx.tid == worker_tid) {
            found = true;
            break;
        }
    }
    if (!found && !contexts.empty()) {
        worker_tid = contexts[0].tid;
        LOG_DBG("Main thread not found, using thread %d for unload", worker_tid);
    }
    
    // Prepare worker thread for injection
    struct user_regs_struct prepared_regs;
    if (!prepare_thread_for_injection(worker_tid, prepared_regs)) {
        restore_and_detach_all(contexts);
        return false;
    }
    
#ifdef DEBUG
    // Verify syscall works before proceeding (debug only)
    if (!test_syscall(worker_tid)) {
        LOG_ERR("Syscall test failed before unload");
        restore_and_detach_all(contexts);
        return false;
    }
#endif
    
    LOG_DBG("Calling unload_library_by_handle with handle=0x%lx", lib.handle);
    bool result = unload_library_by_handle(worker_tid, lib.handle, prepared_regs);
    
    if (result) {
        // Clean up tracker and cache
        invalidate_cache(lib.base_addr);
        tracked_libraries_.erase(it);
        LOG_INFO("Library %s successfully unloaded", lib_path.c_str());
    } else {
        LOG_ERR("Failed to unload library %s", lib_path.c_str());
    }
    
    // Restore and detach all threads
    restore_and_detach_all(contexts);
    
    return result;
}

bool DL_Manager::apply_patch(pid_t tid, const std::string& target_lib_path, uintptr_t old_func,
                              uintptr_t new_func, size_t old_func_size,
                  const std::string& func_name) {
    std::string clean_path = trim(target_lib_path);
    auto lib_it = tracked_libraries_.find(clean_path);
    if (lib_it == tracked_libraries_.end()) {
        LOG_ERR("No tracked library for path %s", clean_path.c_str()); 
        return false;
    }
    TrackedLibrary& target_lib = lib_it->second;

    // Threshold for GOT patching (small functions use GOT)
    const size_t THRESHOLD = 16;

    // GOT patch path - for small functions
    if (old_func_size < THRESHOLD) {
        LOG_INFO("Patching %s via GOT (function size: %zu bytes)", 
                 func_name.c_str(), old_func_size);
        
        uintptr_t got_entry = find_got_entry(target_lib.base_addr, func_name);
        if (got_entry == 0) {
            LOG_WARN("No GOT entry for %s", func_name.c_str());
            return false;
        }
        
        // Save original GOT value for rollback
        uintptr_t orig = 0;
        if (!read_remote_memory(pid_, got_entry, &orig, sizeof(orig))) {
            LOG_ERR("Cannot read original GOT");
            return false;
        }
        target_lib.saved_original_got[func_name] = orig;

        // Write new function address to GOT
        if (!write_remote_memory(tid, got_entry, &new_func, sizeof(new_func))) {
            LOG_ERR("GOT write failed");
            return false;
        }
        
        LOG_DBG("GOT patched %s: 0x%lx -> 0x%lx", func_name.c_str(), orig, new_func);
        return true;
    }

    // JMP patch path - for larger functions
    if (old_func_size < 5) {
        LOG_WARN("Function %s too small for JMP patch (%zu bytes)", 
                 func_name.c_str(), old_func_size);
        return false;
    }

    // Save original bytes for rollback
    uint8_t orig_bytes[5];
    if (!read_remote_memory(pid_, old_func, orig_bytes, 5)) {
        LOG_ERR("Cannot read original bytes for %s", func_name.c_str());
        return false;
    }
    target_lib.saved_original_bytes[func_name] = 
        std::vector<uint8_t>(orig_bytes, orig_bytes + 5);
    
    // Create and write JMP patch
    auto patch = Arch::create_jmp_patch(old_func, new_func);
    if (patch.size() != 5) {
        LOG_ERR("Unexpected jmp patch size for %s", func_name.c_str());
        return false;
    }
    
    if (!write_remote_memory(tid, old_func, patch.data(), patch.size())) {
        LOG_ERR("JMP write failed for %s", func_name.c_str());
        return false;
    }
    
    LOG_DBG("JMP patched %s: 0x%lx -> 0x%lx", func_name.c_str(), old_func, new_func);
    return true;
}

bool DL_Manager::apply_all_patches(pid_t tid, 
                                   const std::string& target_lib_path, 
                                   uintptr_t old_base, 
                                   uintptr_t new_base, 
                                   const std::string& new_lib_path, 
                                   const std::string& target_function) {
    std::string clean_target_path = trim(target_lib_path);
    bool any_success = false;
    int total = 0;
    int succeeded = 0;
    int skipped = 0;
    int failed = 0;
    
    if (target_function == "all") {
        // Get all exported functions from old library
        auto old_symbols = get_function_symbols(old_base);
        LOG_INFO("Found %zu exported functions in old library", old_symbols.size());
        
        std::vector<std::string> patched_functions;
        
        for (const auto& sym : old_symbols) {
            total++;
            const std::string& func_name = sym.name;
            
            // Get function address in new library
            uintptr_t new_func_addr = get_symbol_address(new_base, func_name);
            
            if (new_func_addr == 0) {
                LOG_DBG("Function '%s' not exported in new library, skipping", func_name.c_str());
                skipped++;
                continue;
            }
            
            uintptr_t old_func_addr = sym.addr;
            
            // Apply patch if addresses differ
            if (old_func_addr != new_func_addr) {
                LOG_INFO("Patching %s: 0x%lx -> 0x%lx (size=%zu)", 
                         func_name.c_str(), old_func_addr, new_func_addr, sym.size);
                
                if (apply_patch(tid, target_lib_path, old_func_addr, new_func_addr, sym.size, func_name)) {
                    patched_functions.push_back(func_name);
                    succeeded++;
                    any_success = true;
                } else {
                    LOG_WARN("Failed to patch %s", func_name.c_str());
                    failed++;
                }
            } else {
                LOG_DBG("Function %s already at same address, skipping", func_name.c_str());
                skipped++;
            }
        }
        
        LOG_RESULT("Patching summary: total=%d, succeeded=%d, skipped=%d, failed=%d", 
                   total, succeeded, skipped, failed);
        
        // Update tracker with patched functions
        if (!patched_functions.empty()) {
            tracked_libraries_[new_lib_path].provided_functions = patched_functions;
        }
        
        return any_success;
        
    } else {
        // Patch single function
        uintptr_t old_func = get_symbol_address(old_base, target_function);
        uintptr_t new_func = get_symbol_address(new_base, target_function);
        
        if (old_func == 0) {
            LOG_ERR("Target function '%s' not exported in old library", target_function.c_str());
            return false;
        }
        
        if (new_func == 0) {
            LOG_ERR("Target function '%s' not exported in new library", target_function.c_str());
            return false;
        }
        
        size_t old_size = get_symbol_size(old_base, target_function);
        if (old_size == 0) {
            LOG_WARN("Could not determine size of function '%s', assuming >=5 bytes", 
                     target_function.c_str());
            old_size = 5;
        }
        
        LOG_DBG("Target function at 0x%lx, new at 0x%lx, size=%zu", 
                old_func, new_func, old_size);
        
        if (old_func != new_func) {
            any_success = apply_patch(tid, target_lib_path, old_func, new_func, old_size, target_function);
            if (any_success) {
                tracked_libraries_[new_lib_path].provided_functions.push_back(target_function);
            }
        } else {
            LOG_INFO("Function addresses are identical, no patch needed.");
            any_success = true;
        }
        
        return any_success;
    }
}

bool DL_Manager::check_preconditions(const std::string& target_lib_pattern) {
    if (!is_safe_to_replace(target_lib_pattern)) {
        LOG_ERR("Not safe to replace library: threads are using it");
        return false;
    }
    
    if (dlopen_addr_ == 0 || dlclose_addr_ == 0 || syscall_insn_ == 0) {
        LOG_ERR("Required addresses not initialized. Call init_addresses() first.");
        return false;
    }
    
    return true;
}

LoadResult DL_Manager::ensure_new_library_loaded(pid_t tid, const std::string& new_lib_path,
                                                  uintptr_t& new_lib_base, uintptr_t& new_handle,
                                                  struct user_regs_struct& saved_regs) {
    std::string normalized = normalize_path(new_lib_path);
    
    LOG_DBG("ensure_new_library_loaded: %s", new_lib_path.c_str());
    
    // Get current file info
    time_t current_mtime = 0;
    size_t current_size = 0;
    bool file_info_ok = get_file_info(new_lib_path, current_mtime, current_size);
    
    // Check if library is already loaded in process memory
    uintptr_t existing_base = 0;
    bool in_maps = is_library_in_maps(new_lib_path, existing_base);
    
    // Check if we have it in tracker
    auto it = tracked_libraries_.find(normalized);
    bool in_tracker = (it != tracked_libraries_.end());
    
    // Case 1: Not loaded at all - load fresh copy
    if (!in_maps && !in_tracker) {
        LOG_INFO("Library not loaded, loading fresh copy");
        new_lib_base = load_new_library(tid, new_lib_path, new_handle, saved_regs);
        if (new_lib_base == 0) return LoadResult::FAILED;
        
        TrackedLibrary& lib = tracked_libraries_[normalized];
        lib = TrackedLibrary(normalized, new_handle, new_lib_base, "");
        lib.mtime = file_info_ok ? current_mtime : 0;
        lib.file_size = file_info_ok ? current_size : 0;
        
        LOG_DBG("  loaded fresh: base=0x%lx, handle=0x%lx", new_lib_base, new_handle);
        return LoadResult::LOADED_NEW;
    }
    
    // Case 2: In tracker - check if file changed
    if (in_tracker) {
        TrackedLibrary& lib = it->second;
        
        // Check if file has changed
        bool file_changed = false;
        if (file_info_ok && lib.file_size != 0) {
            if (lib.file_size != current_size) {
                LOG_DBG("  size changed: %zu -> %zu", lib.file_size, current_size);
                file_changed = true;
            } else if (lib.mtime != current_mtime) {
                time_t diff = llabs(lib.mtime - current_mtime);
                if (diff > MTIME_TOLERANCE) {
                    LOG_DBG("  mtime changed significantly: %ld -> %ld", lib.mtime, current_mtime);
                    file_changed = true;
                }
            }
        } else if (file_info_ok && lib.file_size == 0) {
            LOG_DBG("  first time getting valid file info for %s", normalized.c_str());
            lib.mtime = current_mtime;
            lib.file_size = current_size;
        }
        
        if (!file_changed) {
            // Same file, use existing - НИЧЕГО НЕ МЕНЯЕМ
            LOG_INFO("Library already loaded and unchanged, using existing copy");
            new_lib_base = lib.base_addr;
            new_handle = lib.handle;
            LOG_DBG("  using existing: base=0x%lx, handle=0x%lx", new_lib_base, new_handle);
            return LoadResult::USED_EXISTING;  // <-- Новый результат
        } else {
            // File changed, need to reload
            LOG_INFO("Library file changed, reloading");
            
            if (lib.is_active && lib.is_original) {
                LOG_ERR("Cannot reload active original library");
                return LoadResult::FAILED;
            }
            
            // Load new version first
            uintptr_t temp_handle = 0, temp_base = 0;
            temp_base = load_new_library(tid, new_lib_path, temp_handle, saved_regs);
            if (temp_base == 0) return LoadResult::FAILED;
            
            // Unload old version
            if (lib.handle != 0) {
                LOG_DBG("  attempting to unload old version with handle 0x%lx", lib.handle);
                unload_library_by_handle(tid, lib.handle, saved_regs);
            }
            
            // Update tracker
            lib.handle = temp_handle;
            lib.base_addr = temp_base;
            lib.provided_functions.clear();
            lib.mtime = current_mtime;
            lib.file_size = current_size;
            
            new_lib_base = temp_base;
            new_handle = temp_handle;
            
            LOG_INFO("Library reloaded successfully");
            return LoadResult::LOADED_NEW;
        }
    }
    
    // Case 3: In maps but not in tracker
    if (in_maps && !in_tracker) {
        LOG_INFO("Library loaded by process but not tracked, loading our copy");
        
        new_lib_base = load_new_library(tid, new_lib_path, new_handle, saved_regs);
        if (new_lib_base == 0) return LoadResult::FAILED;
        
        TrackedLibrary& lib = tracked_libraries_[normalized];
        lib = TrackedLibrary(normalized, new_handle, new_lib_base, "");
        lib.mtime = file_info_ok ? current_mtime : 0;
        lib.file_size = file_info_ok ? current_size : 0;
        
        LOG_INFO("Library loaded and tracked");
        return LoadResult::LOADED_NEW;
    }
    
    return LoadResult::FAILED;
}

bool DL_Manager::is_library_in_maps(const std::string& lib_path, uintptr_t& base_addr) const {
    std::string maps_path = "/proc/" + std::to_string(pid_) + "/maps";
    std::ifstream maps_file(maps_path);
    if (!maps_file.is_open()) return false;
    
    std::string line;
    while (std::getline(maps_file, line)) {
        if (line.find(lib_path) != std::string::npos) {
            size_t dash = line.find('-');
            if (dash != std::string::npos) {
                base_addr = std::stoul(line.substr(0, dash), nullptr, 16);
                return true;
            }
        }
    }
    return false;
}

bool DL_Manager::wait_for_threads_to_leave_library(const std::vector<pid_t>& all_tids,
                                                    const std::vector<std::pair<uintptr_t, uintptr_t>>& segments,
                                                    std::vector<pid_t>& stopped_tids,
                                                    int max_attempts, int retry_us) {
    stopped_tids.clear();
    std::set<pid_t> remaining(all_tids.begin(), all_tids.end());
    std::map<pid_t, bool> inside;

    for (int attempt = 0; attempt < max_attempts && !remaining.empty(); ++attempt) {
        auto it = remaining.begin();
        while (it != remaining.end()) {
            pid_t tid = *it;

            if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == -1) {
                if (errno == ESRCH) {
                    LOG_WARN("Thread %d no longer exists, removing from list", tid);
                    it = remaining.erase(it);
                    continue;
                }
                LOG_ERR("ptrace ATTACH failed for thread %d, errno=%d", tid, errno);
                ++it;
                continue;
            }

            int status;
            waitpid(tid, &status, 0);
            if (!WIFSTOPPED(status)) {
                LOG_WARN("Thread %d did not stop after attach", tid);
                ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
                ++it;
                continue;
            }

            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) == -1) {
                LOG_ERR("ptrace GETREGS failed for thread %d", tid);
                ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
                ++it;
                continue;
            }

            bool in_lib = address_in_library(Arch::get_ip(regs), segments);
            if (in_lib) {
                LOG_DBG("Thread %d is inside library (IP=0x%lx), detaching and will retry", tid, Arch::get_ip(regs));
                ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
                inside[tid] = true;
                ++it;
            } else {
                LOG_DBG("Thread %d is outside library, stopping permanently", tid);
                stopped_tids.push_back(tid);
                it = remaining.erase(it);
                inside.erase(tid);
            }
        }

        if (!remaining.empty()) {
            LOG_INFO("Still waiting for %zu threads to leave library, attempt %d/%d",
                     remaining.size(), attempt + 1, max_attempts);
            usleep(retry_us);
        }
    }

    if (!remaining.empty()) {
        LOG_ERR("Timeout: %zu threads still inside library after %d attempts", remaining.size(), max_attempts);
        for (pid_t tid : stopped_tids) {
            ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
        }
        stopped_tids.clear();
        return false;
    }

    LOG_INFO("All threads are now outside the library, %zu threads stopped", stopped_tids.size());
    return true;
}

void resume_all_threads(const std::vector<pid_t>& tids) {
    for (pid_t tid : tids) {
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
    }
}

void DL_Manager::cleanup_old_libraries(const std::string& target_lib_path,
                                        const std::string& new_lib_path,
                                        pid_t tid,
                                        struct user_regs_struct& saved_regs) {
    LOG_DBG("Cleaning up old libraries...");
    
    std::string normalized_target = target_lib_path;
    std::string normalized_new = new_lib_path;
    
    std::set<std::string> to_unload;
    for (const auto& pair : tracked_libraries_) {
        const TrackedLibrary& lib = pair.second;
        
        // Skip the new library
        if (lib.path == normalized_new) continue;
        
        // Skip original libraries (can't unload them)
        if (lib.is_original) continue;
        
        // Skip if still active (shouldn't happen, but just in case)
        if (lib.is_active) continue;
        
        // This is an inactive non-original library - can unload
        to_unload.insert(pair.first);
    }
    
    for (const std::string& path : to_unload) {
        auto it = tracked_libraries_.find(path);
        if (it != tracked_libraries_.end() && it->second.handle != 0) {
            LOG_INFO("Unloading unused library: %s", path.c_str());
            
            if (unload_library_by_handle(tid, it->second.handle, saved_regs)) {
                invalidate_cache(it->second.base_addr);
                tracked_libraries_.erase(it);
            } else {
                LOG_ERR("Failed to unload %s", path.c_str());
            }
        }
    }
}

bool DL_Manager::validate_target_library(const std::string& target_lib_pattern, 
                                          LibraryInfo& target_info,
                                          std::string& clean_path,
                                          std::string& normalized_path) {
    // Get target library info from /proc/pid/maps
    target_info = get_library_info(target_lib_pattern);
    if (target_info.base_addr == 0) {
        LOG_ERR("Target library not found in process memory");
        return false;
    }

    clean_path = trim(target_info.path);
    normalized_path = normalize_path(clean_path);
    return true;
}

bool DL_Manager::check_target_safety(const std::string& normalized_target,
                                      time_t target_mtime,
                                      size_t target_size,
                                      bool target_info_ok) {
    auto target_it = tracked_libraries_.find(normalized_target);
    if (target_it == tracked_libraries_.end()) {
        LOG_INFO("Target library not in tracker - assuming it's safe to replace");
        return true;
    }

    TrackedLibrary& target_lib = target_it->second;
    
    // Update file info if changed
    update_tracked_file_info(target_lib, target_mtime, target_size, target_info_ok);
    
    // Check if target is original and active - can't unload original
    if (target_lib.is_active && target_lib.is_original) {
        LOG_WARN("Target is original and active - will be patched but cannot be unloaded");
        // This is fine - we can still patch it, just can't unload the original
    }
    else if (target_lib.is_active && !target_lib.is_original) {
        LOG_WARN("Target library is active and non-original. It will be replaced and then unloaded.");
    }
    else if (target_lib.is_original) {
        LOG_INFO("Target is original library - replacement allowed");
    }
    
    return true;
}

void DL_Manager::ensure_target_in_tracker(const std::string& normalized_target,
                                           const std::string& clean_path,
                                           uintptr_t target_base,
                                           time_t target_mtime,
                                           size_t target_size,
                                           bool target_info_ok) {
    // Skip if already tracked
    if (tracked_libraries_.find(normalized_target) != tracked_libraries_.end()) {
        return;
    }
    
    LOG_DBG("Adding target to tracker: path=%s, base=0x%lx, mtime=%ld, size=%zu, info_ok=%d",
            clean_path.c_str(), target_base, target_mtime, target_size, target_info_ok);
    
    // Add as original library
    TrackedLibrary target_lib(normalized_target, 0, target_base, std::vector<std::string>());
    target_lib.is_original = true;
    
    // Store file info - if get_file_info failed, store 0 (not max values!)
    target_lib.mtime = target_info_ok ? target_mtime : 0;
    target_lib.file_size = target_info_ok ? target_size : 0;
    
    tracked_libraries_[normalized_target] = target_lib;
    LOG_INFO("Added target library to tracker: %s", clean_path.c_str());
}

bool DL_Manager::freeze_threads_outside_library(const std::vector<pid_t>& all_tids,
                                                 const std::vector<std::pair<uintptr_t, uintptr_t>>& segments,
                                                 std::vector<ThreadContext>& contexts) {
    const int MAX_ATTEMPTS = 50;
    const int RETRY_US = 10000;

    for (int attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
        if (!stop_all_threads(all_tids, contexts)) {
            LOG_ERR("Failed to stop threads on attempt %d", attempt + 1);
            return false;
        }

        // Check if all threads are outside the library
        if (all_threads_outside(contexts, segments)) {
            return true;
        }

        // Still inside - detach and retry
        restore_and_detach_all(contexts);
        contexts.clear();
        usleep(RETRY_US);
    }

    LOG_ERR("Failed to freeze all threads outside the library after %d attempts", MAX_ATTEMPTS);
    return false;
}

void DL_Manager::select_worker_thread(const std::vector<ThreadContext>& contexts, pid_t& worker_tid) {
    // Prefer main thread (pid_)
    for (const auto& ctx : contexts) {
        if (ctx.tid == pid_) {
            worker_tid = ctx.tid;
            return;
        }
    }
    
    // Fallback to first available thread
    worker_tid = contexts[0].tid;
    LOG_INFO("Main thread not found, using thread %d for injection", worker_tid);
}

void DL_Manager::update_active_status(const std::string& normalized_new) {
    // Only the new library remains active
    for (auto& pair : tracked_libraries_) {
        pair.second.is_active = (pair.first == normalized_new);
    }
}

void DL_Manager::record_patched_library(const std::string& normalized_new, const std::string& target_path) {
    auto new_lib_it = tracked_libraries_.find(normalized_new);
    if (new_lib_it != tracked_libraries_.end()) {
        new_lib_it->second.is_active = true;
        new_lib_it->second.patched_libraries.push_back(target_path);
    }
}

//=============================================================================
// Main replacement function 
//=============================================================================
bool DL_Manager::replace_library(const std::string& target_lib_pattern,
                                  const std::string& new_lib_path,
                                  const std::string& target_function) {
    log_replacement_start(target_lib_pattern, new_lib_path, target_function);

    // Check required addresses
    if (!check_required_addresses(dlopen_addr_, dlclose_addr_, syscall_insn_)) {
        log_replacement_result(false);
        return false;
    }

    // Validate target library
    LibraryInfo target_info;
    std::string clean_target_path, normalized_target;
    if (!validate_target_library(target_lib_pattern, target_info, clean_target_path, normalized_target)) {
        log_replacement_result(false);
        return false;
    }

    // Normalize new library path
    std::string normalized_new = normalize_path(new_lib_path);

    // Get file info for change detection
    time_t target_mtime = 0, new_mtime = 0;
    size_t target_size = 0, new_size = 0;
    bool target_info_ok = get_file_info(clean_target_path, target_mtime, target_size);
    bool new_info_ok = get_file_info(new_lib_path, new_mtime, new_size);

    LOG_DBG("Target file: path=%s, ok=%d, mtime=%ld, size=%zu", 
            clean_target_path.c_str(), target_info_ok, target_mtime, target_size);
    LOG_DBG("New file: path=%s, ok=%d, mtime=%ld, size=%zu", 
            new_lib_path.c_str(), new_info_ok, new_mtime, new_size);

    // Check if target is safe to replace
    if (!check_target_safety(normalized_target, target_mtime, target_size, target_info_ok)) {
        log_replacement_result(false);
        return false;
    }

    // Ensure target is in tracker
    ensure_target_in_tracker(normalized_target, clean_target_path, target_info.base_addr,
                             target_mtime, target_size, target_info_ok);

    // Get all threads
    std::vector<pid_t> all_tids = get_all_threads(pid_);
    if (all_tids.empty()) {
        LOG_ERR("No threads found - process may have terminated");
        log_replacement_result(false);
        return false;
    }

    // Freeze threads outside target library
    std::vector<ThreadContext> contexts;
    if (!freeze_threads_outside_library(all_tids, target_info.segments, contexts)) {
        log_replacement_result(false);
        return false;
    }

    // Select worker thread
    pid_t worker_tid;
    select_worker_thread(contexts, worker_tid);

    // Prepare worker thread for injection
    struct user_regs_struct prepared_regs;
    if (!prepare_thread_for_injection(worker_tid, prepared_regs)) {
        restore_and_detach_all(contexts);
        log_replacement_result(false);
        return false;
    }

    LOG_DBG("Prepared IP=0x%llx, SP=0x%llx", 
            (unsigned long long)Arch::get_ip(prepared_regs), 
            (unsigned long long)Arch::get_sp(prepared_regs));

    struct user_regs_struct saved_regs = prepared_regs;

    // Verify syscall works
    if (!test_syscall(worker_tid)) {
        LOG_ERR("Syscall test failed");
        restore_and_detach_all(contexts);
        log_replacement_result(false);
        return false;
    }

    // Load new library - get result to know if we need to apply patches
    uintptr_t new_lib_base = 0, new_handle = 0;
    LoadResult load_result = ensure_new_library_loaded(worker_tid, normalized_new, 
                                                        new_lib_base, new_handle, saved_regs);
    
    if (load_result == LoadResult::FAILED) {
        LOG_ERR("Failed to load new library");
        restore_and_detach_all(contexts);
        log_replacement_result(false);
        return false;
    }
    
    bool patch_success = true;
    
    // Apply patches ONLY if a new library was actually loaded
    if (load_result == LoadResult::LOADED_NEW) {
        LOG_INFO("New library loaded, applying patches");
        patch_success = apply_all_patches(worker_tid, normalized_target, 
                                           target_info.base_addr, new_lib_base,
                                           normalized_new, target_function);
        
        if (patch_success) {
            // Update tracker state - only new library is active now
            update_active_status(normalized_new);
            record_patched_library(normalized_new, target_info.path);
            
            // Clean up old libraries (including the previous active non-original if any)
            cleanup_old_libraries(normalized_target, normalized_new, worker_tid, saved_regs);
            
            // Start daemon if needed
            ensure_daemon_running();
        }
    } else {
        // USED_EXISTING - library unchanged, patches already applied
        LOG_INFO("Library unchanged, skipping patch application (already patched)");
        
        // Still ensure active status is correct
        update_active_status(normalized_new);
        
        // Still clean up old libraries (in case there are any hanging around)
        cleanup_old_libraries(normalized_target, normalized_new, worker_tid, saved_regs);
    }

    // Restore registers and detach all threads
    restore_and_detach_all(contexts);
    
    log_replacement_result(patch_success);
    return patch_success;
}
