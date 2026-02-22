// Updated DL_manager_replace.ipp with fixed stop_all_threads calls

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

// Constants
static const size_t REMOTE_MEM_SIZE = 4096;
static const size_t SHELLCODE_PATH_OFFSET = 256;
static const size_t SHELLCODE_RESULT_OFFSET = 512;

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
        if (address_in_library(ctx.regs.rip, segments)) {
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
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    uintptr_t start_word = addr & ~(sizeof(long) - 1);
    uintptr_t end_word = (addr + size + sizeof(long) - 1) & ~(sizeof(long) - 1);
    
    LOG_DBG("Writing %zu bytes to 0x%lx, word range 0x%lx-0x%lx", 
            size, addr, start_word, end_word);

    for (uintptr_t w = start_word; w < end_word; w += sizeof(long)) {
        long word = 0;
        bool need_read = false;
        
        if (w < addr || w + sizeof(long) > addr + size) {
            need_read = true;
        }
        
        if (need_read) {
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, pid, w, nullptr);
            if (word == -1 && errno != 0) {
                LOG_ERR("ptrace PEEKDATA failed at 0x%lx: %s", w, strerror(errno));
                return false;
            }
            LOG_DBG("Read word at 0x%lx: 0x%016lx", w, word);
        }
        
        size_t src_offset = (w > addr) ? 0 : (addr - w);
        size_t dst_offset = (w < addr) ? (addr - w) : 0;
        size_t copy_len = std::min(sizeof(long) - dst_offset, 
                                   size - (w - addr + dst_offset));
        
        LOG_DBG("Word 0x%lx: dst_offset=%zu, src_offset=%zu, copy_len=%zu", 
                w, dst_offset, src_offset, copy_len);
        
        memcpy(reinterpret_cast<uint8_t*>(&word) + dst_offset, 
               bytes + src_offset + (w - addr), copy_len);
        
        LOG_DBG("Writing word at 0x%lx: 0x%016lx", w, word);
        
        if (ptrace(PTRACE_POKEDATA, pid, w, word) == -1) {
            LOG_ERR("ptrace POKEDATA failed at 0x%lx: %s", w, strerror(errno));
            return false;
        }
        
#ifdef DEBUG
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
    struct iovec local = {buffer, size};
    struct iovec remote = {reinterpret_cast<void*>(addr), size};
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    return n == static_cast<ssize_t>(size);
}

static bool remote_syscall(pid_t pid, uintptr_t& result,
                           long number,
                           uintptr_t arg1, uintptr_t arg2,
                           uintptr_t arg3, uintptr_t arg4,
                           uintptr_t arg5, uintptr_t arg6,
                           uintptr_t syscall_insn_addr) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
        LOG_ERR("ptrace GETREGS failed");
        return false;
    }

    struct user_regs_struct saved_regs = regs;

    regs.rax = number;
    regs.rdi = arg1;
    regs.rsi = arg2;
    regs.rdx = arg3;
    regs.r10 = arg4;
    regs.r8  = arg5;
    regs.r9  = arg6;
    regs.rip = syscall_insn_addr;

    if (ptrace(PTRACE_SETREGS, pid, nullptr, &regs) == -1) {
        LOG_ERR("ptrace SETREGS failed");
        return false;
    }

    if (ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr) == -1) {
        LOG_ERR("ptrace SINGLESTEP failed");
        ptrace(PTRACE_SETREGS, pid, nullptr, &saved_regs);
        return false;
    }

    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        LOG_ERR("Process terminated during syscall");
        return false;
    }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        LOG_ERR("Unexpected stop after syscall: signal=%d", WSTOPSIG(status));
        ptrace(PTRACE_SETREGS, pid, nullptr, &saved_regs);
        return false;
    }

    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
        LOG_ERR("ptrace GETREGS after syscall failed");
        ptrace(PTRACE_SETREGS, pid, nullptr, &saved_regs);
        return false;
    }
    result = regs.rax;

    ptrace(PTRACE_SETREGS, pid, nullptr, &saved_regs);
    return true;
}

static uintptr_t remote_mmap(pid_t pid, size_t length, int prot, int flags, int fd, off_t offset,
                             uintptr_t syscall_insn_addr) {
    uintptr_t result;
    if (!remote_syscall(pid, result, 9, 0, length, prot, flags, fd, offset, syscall_insn_addr)) {
        return 0;
    }
    if (result == ~0ULL) {
        LOG_ERR("remote mmap failed");
        return 0;
    }
    return result;
}

static bool remote_munmap(pid_t pid, uintptr_t addr, size_t length, uintptr_t syscall_insn_addr) {
    uintptr_t result;
    if (!remote_syscall(pid, result, 11, addr, length, 0, 0, 0, 0, syscall_insn_addr)) {
        return false;
    }
    if (result != 0) {
        LOG_ERR("remote munmap failed");
        return false;
    }
    return true;
}

// ============================================================================
// DL_Manager implementation
// ============================================================================

void DL_Manager::init_addresses() {
    LibraryInfo libc_info = get_library_info("libc.so");
    if (libc_info.base_addr == 0) {
        LOG_WARN("libc not found, some features may not work");
        return;
    }
    
    dlopen_addr_ = get_symbol_address(libc_info.base_addr, "dlopen");
    dlclose_addr_ = get_symbol_address(libc_info.base_addr, "dlclose");
    syscall_insn_ = find_syscall_instruction(libc_info.base_addr);
    
    LOG_INFO("Initialized addresses: dlopen=0x%lx, dlclose=0x%lx, syscall=0x%lx",
             dlopen_addr_, dlclose_addr_, syscall_insn_);
}

uintptr_t DL_Manager::find_syscall_instruction(uintptr_t libc_base) {
    uintptr_t syscall_func = get_symbol_address(libc_base, "syscall");
    if (syscall_func == 0) {
        LOG_ERR("Failed to find syscall symbol");
        return 0;
    }
    
    unsigned char buffer[64];
    if (!read_remote_memory(pid_, syscall_func, buffer, sizeof(buffer))) {
        LOG_ERR("Failed to read syscall function");
        return 0;
    }
    
    for (int i = 0; i < (int)sizeof(buffer) - 1; ++i) {
        if (buffer[i] == 0x0f && buffer[i+1] == 0x05) {
            uintptr_t candidate = syscall_func + i;
            std::string maps_path = "/proc/" + std::to_string(pid_) + "/maps";
            std::ifstream maps_file(maps_path);
            if (maps_file.is_open()) {
                std::string line;
                while (std::getline(maps_file, line)) {
                    size_t dash = line.find('-');
                    if (dash == std::string::npos) continue;
                    uintptr_t start = std::stoul(line.substr(0, dash), nullptr, 16);
                    size_t space = line.find(' ', dash);
                    if (space == std::string::npos) continue;
                    uintptr_t end = std::stoul(line.substr(dash + 1, space - dash - 1), nullptr, 16);
                    if (candidate >= start && candidate < end) {
                        size_t perms_start = space + 1;
                        size_t perms_end = line.find(' ', perms_start);
                        std::string perms = line.substr(perms_start, perms_end - perms_start);
                        if (perms.find('x') != std::string::npos) {
                            LOG_INFO("Found syscall instruction at 0x%lx", candidate);
                            return candidate;
                        }
                    }
                }
            }
        }
    }
    LOG_ERR("No syscall instruction found in first 64 bytes");
    return 0;
}

bool DL_Manager::is_library_already_loaded(const std::string& lib_path, uintptr_t& base_addr, uintptr_t& handle) {
    auto it = tracked_libraries_.find(lib_path);
    if (it != tracked_libraries_.end()) {
        base_addr = it->second.base_addr;
        handle = it->second.handle;
        return true;
    }
    
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

bool DL_Manager::test_syscall(pid_t tid) {
    if (syscall_insn_ == 0) return false;
    uintptr_t result;
    if (!remote_syscall(tid, result, 39, 0, 0, 0, 0, 0, 0, syscall_insn_)) {
        LOG_ERR("Test syscall failed");
        return false;
    }
    LOG_DBG("Test getpid returned %lu", result);
    return true;
}

std::vector<pid_t> DL_Manager::stop_threads_and_prepare_main(pid_t& main_tid, 
                                                              struct user_regs_struct& saved_regs) {
    std::vector<pid_t> tids = get_all_threads(pid_);
    if (tids.empty()) {
        LOG_ERR("No threads found");
        return {};
    }
    
    std::vector<ThreadContext> contexts;
    if (!stop_all_threads(tids, contexts)) {
        return {};
    }
    
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
    
    for (int i = 0; i < 2; ++i) {
        if (ptrace(PTRACE_SYSCALL, main_tid, nullptr, nullptr) == -1) {
            LOG_ERR("ptrace SYSCALL failed");
            restore_and_detach_all(contexts);
            return {};
        }
        int status;
        waitpid(main_tid, &status, 0);
        if (!WIFSTOPPED(status)) {
            LOG_ERR("Thread did not stop after PTRACE_SYSCALL");
            restore_and_detach_all(contexts);
            return {};
        }
    }
    
    if (ptrace(PTRACE_GETREGS, main_tid, nullptr, &saved_regs) == -1) {
        LOG_ERR("ptrace GETREGS failed");
        restore_and_detach_all(contexts);
        return {};
    }
    
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

bool DL_Manager::write_shellcode_with_verification(pid_t tid, uintptr_t shellcode_addr,
                                                   uintptr_t path_addr, uintptr_t result_addr) {
    unsigned char shellcode[] = {
        0x55,                               // push rbp
        0x48, 0x89, 0xe5,                   // mov rbp, rsp
        0x57,                               // push rdi
        0x56,                               // push rsi
        0x50,                               // push rax
        0x48, 0x83, 0xec, 0x08,             // sub rsp, 8     
        
        0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rdi, path_addr
        0x48, 0xc7, 0xc6, 0x02, 0x00, 0x00, 0x00,                    // mov rsi, 2 (RTLD_NOW)
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, dlopen_addr
        0xff, 0xd0,                                                    // call rax
        
        0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rdi, result_addr
        0x48, 0x89, 0x07,                                              // mov [rdi], rax
        
        0x48, 0x83, 0xc4, 0x08,             // add rsp, 8     
        0x58,                               // pop rax
        0x5e,                               // pop rsi
        0x5f,                               // pop rdi
        0x5d,                               // pop rbp
        0xcc,                               // int3
        0xc3                                // ret
    };
    
    const size_t PATH_OFFSET = 13;      // after sub rsp,8 and opcode mov rdi (48 bf)
    const size_t DLOPEN_OFFSET = 30;    // after  mov rsi and opcode mov rax (48 b8)
    const size_t RESULT_OFFSET = 42;    // after call and opcode 2nd mov rdi (48 bf)
    
    LOG_DBG("Shellcode layout: PATH_OFFSET=%zu, DLOPEN_OFFSET=%zu, RESULT_OFFSET=%zu",
            PATH_OFFSET, DLOPEN_OFFSET, RESULT_OFFSET);
    LOG_DBG("Shellcode size: %zu bytes", sizeof(shellcode));
    
    *reinterpret_cast<uintptr_t*>(shellcode + PATH_OFFSET) = path_addr;
    *reinterpret_cast<uintptr_t*>(shellcode + DLOPEN_OFFSET) = dlopen_addr_;
    *reinterpret_cast<uintptr_t*>(shellcode + RESULT_OFFSET) = result_addr;    

    LOG_DBG("Shellcode before writing:");
    for (size_t i = 0; i < sizeof(shellcode); i += 8) {
        size_t chunk = std::min(sizeof(shellcode) - i, size_t(8));
        uint64_t val = 0;
        memcpy(&val, shellcode + i, chunk);
        LOG_DBG("  offset %3zu: 0x%016lx", i, val);
    }
    
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

    test_val = 0;
    write_remote_memory(tid, result_addr, &test_val, sizeof(test_val));
    LOG_DBG("result_addr is writable");
    
    if (!write_remote_memory(tid, shellcode_addr, shellcode, sizeof(shellcode))) {
        LOG_ERR("Failed to write shellcode");
        return false;
    }
    
    unsigned char verify[sizeof(shellcode)];
    if (!read_remote_memory(tid, shellcode_addr, verify, sizeof(verify))) {
        LOG_ERR("Failed to read back shellcode for verification");
        return false;
    }
    
    if (memcmp(verify, shellcode, sizeof(shellcode)) != 0) {
        LOG_ERR("Shellcode verification failed!");
        for (size_t i = 0; i < sizeof(shellcode); i += 8) {
            size_t chunk = std::min(sizeof(shellcode) - i, size_t(8));
            uint64_t orig = 0, ver = 0;
            memcpy(&orig, shellcode + i, chunk);
            memcpy(&ver, verify + i, chunk);
            if (orig != ver) {
                LOG_ERR("  Mismatch at offset %zu: wrote 0x%016lx, read 0x%016lx", 
                        i, orig, ver);
            }
        }
        return false;
    }
    
    LOG_DBG("Shellcode written and verified successfully");
    return true;
}

bool DL_Manager::execute_shellcode_and_get_handle(pid_t tid, uintptr_t shellcode_addr,
                                                   struct user_regs_struct& saved_regs,
                                                   uintptr_t& out_handle) {
    struct user_regs_struct new_regs = saved_regs;
    new_regs.rip = shellcode_addr;
    
    LOG_DBG("Setting RIP to 0x%lx, original RSP=0x%lx", shellcode_addr, saved_regs.rsp);
    
    if (ptrace(PTRACE_SETREGS, tid, nullptr, &new_regs) == -1) {
        LOG_ERR("ptrace SETREGS failed: %s", strerror(errno));
        return false;
    }
    
    if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) == -1) {
        LOG_ERR("ptrace CONT failed: %s", strerror(errno));
        return false;
    }
    
    int status;
    waitpid(tid, &status, 0);
    
    uintptr_t handle = 0;
    uintptr_t result_addr = shellcode_addr + SHELLCODE_RESULT_OFFSET;
    
    if (WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);
        LOG_INFO("Thread stopped with signal %d", sig);
        
        if (sig == SIGTRAP) {
            LOG_INFO("Got SIGTRAP as expected");
            if (read_remote_memory(tid, result_addr, &handle, sizeof(handle))) {
                LOG_INFO("Handle from result_addr: 0x%lx", handle);
                if (handle != 0) {
                    out_handle = handle;
                    
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
            LOG_ERR("Segmentation fault in shellcode");
            
            siginfo_t siginfo;
            if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, &siginfo) == 0) {
                LOG_ERR("Fault address: 0x%lx, code: %d", 
                        (uintptr_t)siginfo.si_addr, siginfo.si_code);
                
                struct user_regs_struct fault_regs;
                if (ptrace(PTRACE_GETREGS, tid, nullptr, &fault_regs) == 0) {
                    LOG_ERR("Fault registers:");
                    LOG_ERR("  RIP=0x%llx", (unsigned long long)fault_regs.rip);
                    LOG_ERR("  RSP=0x%llx", (unsigned long long)fault_regs.rsp);
                    LOG_ERR("  RAX=0x%llx", (unsigned long long)fault_regs.rax);
                    LOG_ERR("  RDI=0x%llx", (unsigned long long)fault_regs.rdi);
                    LOG_ERR("  RSI=0x%llx", (unsigned long long)fault_regs.rsi);
                    
                    unsigned char code_dump[32];
                    uintptr_t dump_addr = fault_regs.rip & ~0xf;
                    if (read_remote_memory(tid, dump_addr, code_dump, sizeof(code_dump))) {
                        LOG_ERR("Code around fault address:");
                        for (int i = 0; i < 32; i += 8) {
                            uint64_t val;
                            memcpy(&val, code_dump + i, 8);
                            LOG_ERR("  0x%lx: 0x%016lx", dump_addr + i, val);
                        }
                    }
                }
            }
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

    LOG_INFO("load_new_library: tid=%d, lib_path=%s", tid, lib_path.c_str());
    LOG_INFO("dlopen_addr=0x%lx, syscall_insn=0x%lx", dlopen_addr_, syscall_insn_);

    // Test syscall mechanism first
    uintptr_t test_result;
    if (!remote_syscall(tid, test_result, 39, 0, 0, 0, 0, 0, 0, syscall_insn_)) {
        LOG_ERR("remote_syscall test failed before allocation");
        return 0;
    }
    LOG_INFO("remote_syscall test passed, result=%lu", test_result);

    uintptr_t remote_mem = allocate_remote_memory(tid, REMOTE_MEM_SIZE);
    if (remote_mem == 0) {
        LOG_ERR("allocate_remote_memory failed");
        return 0;
    }
    LOG_INFO("remote_mem allocated at 0x%lx", remote_mem);

    uintptr_t path_addr = remote_mem + SHELLCODE_PATH_OFFSET;
    uintptr_t result_addr = remote_mem + SHELLCODE_RESULT_OFFSET;
    
    LOG_INFO("path_addr = 0x%lx, result_addr = 0x%lx", path_addr, result_addr);

    if (!write_remote_memory(tid, path_addr, lib_path.c_str(), lib_path.size() + 1)) {
        LOG_ERR("Failed to write library path");
        remote_munmap(pid_, remote_mem, REMOTE_MEM_SIZE, syscall_insn_);
        return 0;
    }
    LOG_INFO("Library path written to 0x%lx", path_addr);

    // Verify path was written correctly
    char path_check[256] = {0};
    if (read_remote_memory(tid, path_addr, path_check, lib_path.size() + 1)) {
        LOG_INFO("Path verification: %s", path_check);
    }

    if (!write_shellcode_with_verification(tid, remote_mem, path_addr, result_addr)) {
        LOG_ERR("Failed to write shellcode");
        remote_munmap(pid_, remote_mem, REMOTE_MEM_SIZE, syscall_insn_);
        return 0;
    }
    LOG_INFO("Shellcode written to 0x%lx", remote_mem);

    // Execute shellcode and get handle
    if (!execute_shellcode_and_get_handle(tid, remote_mem, saved_regs, out_handle)) {
        LOG_ERR("execute_shellcode_and_get_handle failed");
        remote_munmap(pid_, remote_mem, REMOTE_MEM_SIZE, syscall_insn_);
        return 0;
    }

    LOG_INFO("Cleaning up remote memory");
    remote_munmap(pid_, remote_mem, REMOTE_MEM_SIZE, syscall_insn_);

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
    if (dlclose_addr_ == 0 || syscall_insn_ == 0) {
        LOG_ERR("Required addresses not initialized");
        return false;
    }
    
    if (handle == 0) {
        LOG_ERR("Invalid handle (0)");
        return false;
    }
    
    size_t mem_size = 256;
    uintptr_t remote_mem = remote_mmap(tid, mem_size,
                                       PROT_READ | PROT_WRITE | PROT_EXEC,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0,
                                       syscall_insn_);
    if (remote_mem == 0) {
        LOG_ERR("Failed to allocate remote memory for unload");
        return false;
    }
    
    unsigned char shellcode[] = {
        0x55,                               // push rbp
        0x48, 0x89, 0xe5,                   // mov rbp, rsp
        0x57,                               // push rdi
        0x50,                               // push rax
        0x48, 0x83, 0xec, 0x08,             // sub rsp, 8     ; align
        
        0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rdi, handle
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, dlclose_addr
        0xff, 0xd0,                                                    // call rax
        
        0x48, 0x83, 0xc4, 0x08,             // add rsp, 8     ; restore stack
        0x58,                               // pop rax
        0x5f,                               // pop rdi
        0x5d,                               // pop rbp
        0xcc,                               // int3
        0xc3                                // ret
    };
    
    const size_t HANDLE_OFFSET = 19;      // after sub rsp,8 and opcode mov rdi
    const size_t DLCLOSE_OFFSET = 29;     // after mov rdi and opcode mov rax
    
    *reinterpret_cast<uintptr_t*>(shellcode + HANDLE_OFFSET) = handle;
    *reinterpret_cast<uintptr_t*>(shellcode + DLCLOSE_OFFSET) = dlclose_addr_;
    
    LOG_DBG("Unload shellcode: HANDLE_OFFSET=%zu, DLCLOSE_OFFSET=%zu", 
            HANDLE_OFFSET, DLCLOSE_OFFSET);
    LOG_DBG("Shellcode size: %zu bytes", sizeof(shellcode));
    
    if (!write_remote_memory(tid, remote_mem, shellcode, sizeof(shellcode))) {
        LOG_ERR("Failed to write unload shellcode");
        remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
        return false;
    }
    
    struct user_regs_struct new_regs = saved_regs;
    new_regs.rip = remote_mem;
    
    if (ptrace(PTRACE_SETREGS, tid, nullptr, &new_regs) == -1) {
        LOG_ERR("ptrace SETREGS for unload failed");
        remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
        return false;
    }
    
    if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) == -1) {
        LOG_ERR("ptrace CONT for unload failed");
    }
    
    int status;
    waitpid(tid, &status, 0);
    
    bool success = false;
    
    if (WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);
        LOG_DBG("Unload thread stopped with signal %d", sig);
        
        if (sig == SIGTRAP) {
            LOG_DBG("dlclose completed successfully (SIGTRAP)");
            success = true;
        } else {
            LOG_WARN("Unload thread stopped with signal %d, assuming success", sig);
            
            success = true;
        }
    } else if (WIFEXITED(status)) {
        LOG_ERR("Thread exited during unload with status %d", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        LOG_ERR("Thread terminated with signal %d during unload", WTERMSIG(status));
    }
    
    if (ptrace(PTRACE_SETREGS, tid, nullptr, &saved_regs) == -1) {
        LOG_ERR("Failed to restore registers after unload");
    }
    
    remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
    
    return success;
}

bool DL_Manager::apply_patch(pid_t tid, uintptr_t old_lib_base, uintptr_t old_func,
                              uintptr_t new_func, size_t old_func_size,
                              const std::string& func_name,
                              struct user_regs_struct& /*saved_regs*/) {
    const size_t THRESHOLD = 16; // функции меньше этого размера патентуем через GOT

    if (old_func_size < THRESHOLD) {
        LOG_INFO("Function '%s' is small (%zu bytes), trying GOT patch", func_name.c_str(), old_func_size);
        uintptr_t got_entry = find_got_entry(old_lib_base, func_name);
        if (got_entry == 0) {
            LOG_WARN("No GOT entry found for '%s', cannot patch", func_name.c_str());
            return false;
        }

        if (!write_remote_memory(tid, got_entry, &new_func, sizeof(new_func))) {
            LOG_ERR("Failed to write GOT entry at 0x%lx", got_entry);
            return false;
        }

#ifdef DEBUG
        uintptr_t verify;
        if (!read_remote_memory(tid, got_entry, &verify, sizeof(verify)) || verify != new_func) {
            LOG_ERR("GOT patch verification failed at 0x%lx", got_entry);
            return false;
        }
#endif

        LOG_INFO("GOT patch applied: %s -> 0x%lx (GOT entry 0x%lx)", func_name.c_str(), new_func, got_entry);
        return true;
    }

    if (old_func_size < 5) {
        LOG_WARN("Function '%s' is too small (%zu bytes) for jmp patch, skipping", 
                 func_name.c_str(), old_func_size);
        return false;
    }

    int32_t rel32 = static_cast<int32_t>(new_func - (old_func + 5));
    unsigned char patch[5] = {0xE9, 0, 0, 0, 0};
    memcpy(patch + 1, &rel32, 4);

    if (!write_remote_memory(tid, old_func, patch, 5)) {
        LOG_ERR("Failed to write patch at 0x%lx", old_func);
        return false;
    }

#ifdef DEBUG
    unsigned char verify[5];
    if (!read_remote_memory(tid, old_func, verify, 5)) {
        LOG_ERR("Failed to read back patch for verification");
        return false;
    }
    if (memcmp(verify, patch, 5) != 0) {
        LOG_ERR("Patch verification failed at 0x%lx", old_func);
        return false;
    }
#endif

    LOG_INFO("JMP patch applied: 0x%lx -> 0x%lx (%s)", old_func, new_func, func_name.c_str());
    return true;
}

void DL_Manager::print_library_tracker() const {
    LOG_INFO("=== Library Tracker Status ===");
    LOG_INFO("Tracked libraries: %zu", tracked_libraries_.size());
    
    for (const auto& pair : tracked_libraries_) {
        const TrackedLibrary& lib = pair.second;
        LOG_INFO("  Path: %s", lib.path.c_str());
        LOG_INFO("    Handle   : 0x%lx", lib.handle);
        LOG_INFO("    Base     : 0x%lx", lib.base_addr);
        LOG_INFO("    Functions: %s", lib.provided_functions.empty() ? "(none)" : "");
        for (const auto& f : lib.provided_functions) {
            LOG_INFO("      - %s", f.c_str());
        }
        LOG_INFO("    Active   : %s", lib.is_active ? "yes" : "no");
        LOG_INFO("    Original : %s", lib.is_original ? "yes" : "no");
        LOG_INFO("    Patched libs: %zu", lib.patched_libraries.size());
    }
    LOG_INFO("==============================");
}

bool DL_Manager::unload_library(const std::string& lib_path) {
    auto it = tracked_libraries_.find(lib_path);
    if (it == tracked_libraries_.end()) {
        LOG_ERR("Library %s not found in tracker", lib_path.c_str());
        return false;
    }
    
    TrackedLibrary& lib = it->second;
    if (lib.is_active) {
        LOG_ERR("Cannot unload active library");
        return false;
    }
    if (lib.is_original) {
        LOG_ERR("Cannot unload original library");
        return false;
    }
    
    struct user_regs_struct saved_regs;
    pid_t main_tid;
    std::vector<ThreadContext> contexts;
    std::vector<pid_t> tids = get_all_threads(pid_);
    
    if (!stop_all_threads(tids, contexts)) {
        return false;
    }
    
    // Find main thread
    main_tid = pid_;
    bool found = false;
    for (const auto& ctx : contexts) {
        if (ctx.tid == main_tid) {
            saved_regs = ctx.regs;
            found = true;
            break;
        }
    }
    if (!found && !contexts.empty()) {
        main_tid = contexts[0].tid;
        saved_regs = contexts[0].regs;
    }
    
    bool result = unload_library_by_handle(main_tid, lib.handle, saved_regs);
    if (result) tracked_libraries_.erase(it);
    
    restore_and_detach_all(contexts);
    
    return result;
}

bool DL_Manager::apply_all_patches(pid_t tid, uintptr_t old_base, uintptr_t new_base,
                                     const std::string& new_lib_path,
                                     const std::string& target_function,
                                     struct user_regs_struct& saved_regs) {
    bool all_success = true;
    
    if (target_function == "all") {
        auto old_symbols = get_function_symbols(old_base);
        LOG_INFO("Found %zu functions in old library", old_symbols.size());
        
        std::vector<std::string> patched_functions;
        
        for (const auto& sym : old_symbols) {
            const std::string& func_name = sym.name;
            uintptr_t old_func_addr = sym.addr;
            uintptr_t new_func_addr = get_symbol_address(new_base, func_name);
            if (new_func_addr == 0) {
                LOG_WARN("Function '%s' not found in new library, skipping", func_name.c_str());
                continue;
            }
            
            if (old_func_addr != new_func_addr) {
                LOG_DBG("Patching %s: 0x%lx -> 0x%lx (size=%zu)", 
                        func_name.c_str(), old_func_addr, new_func_addr, sym.size);
                // Передаём old_base, old_func_addr, new_func_addr, sym.size, ...
                if (apply_patch(tid, old_base, old_func_addr, new_func_addr, sym.size, func_name, saved_regs)) {
                    patched_functions.push_back(func_name);
                } else {
                    LOG_ERR("Failed to patch %s", func_name.c_str());
                    all_success = false;
                }
            } else {
                LOG_DBG("Function %s already at same address, skipping", func_name.c_str());
            }
        }
        
        if (!patched_functions.empty()) {
            tracked_libraries_[new_lib_path].provided_functions = patched_functions;
        }
    } else {
        uintptr_t old_func = get_symbol_address(old_base, target_function);
        uintptr_t new_func = get_symbol_address(new_base, target_function);
        
        if (old_func == 0 || new_func == 0) {
            LOG_ERR("Failed to find target function '%s' in libraries", target_function.c_str());
            return false;
        }
        
        size_t old_size = get_symbol_size(old_base, target_function);
        if (old_size == 0) {
            LOG_WARN("Could not determine size of function '%s', assuming >=5 bytes", target_function.c_str());
            old_size = 5;
        }
        
        LOG_DBG("Target function at 0x%lx, new at 0x%lx, size=%zu", old_func, new_func, old_size);
        
        if (old_func != new_func) {
            all_success = apply_patch(tid, old_base, old_func, new_func, old_size, target_function, saved_regs);
            if (all_success) {
                tracked_libraries_[new_lib_path].provided_functions.push_back(target_function);
            }
        } else {
            LOG_INFO("Function addresses are identical, no patch needed.");
            all_success = true;
        }
    }
    
    return all_success;
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

bool DL_Manager::ensure_new_library_loaded(pid_t tid, const std::string& new_lib_path,
                                           uintptr_t& new_lib_base, uintptr_t& new_handle,
                                           struct user_regs_struct& saved_regs) {
    bool already_loaded = is_library_already_loaded(new_lib_path, new_lib_base, new_handle);
    if (!already_loaded) {
        new_lib_base = load_new_library(tid, new_lib_path, new_handle, saved_regs);
        if (new_lib_base == 0) return false;
        
        tracked_libraries_[new_lib_path] = TrackedLibrary(new_lib_path, new_handle, new_lib_base, "");
        LOG_INFO("New library added to tracker");
    } else {
        LOG_INFO("Library already loaded, using existing copy.");
    }
    return true;
}

bool DL_Manager::apply_patches_and_update_tracker(pid_t tid, uintptr_t target_base, uintptr_t new_base,
                                                  const std::string& new_lib_path, const std::string& target_func,
                                                  struct user_regs_struct& saved_regs) {
    return apply_all_patches(tid, target_base, new_base, new_lib_path, target_func, saved_regs);
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

            bool in_lib = address_in_library(regs.rip, segments);
            if (in_lib) {
                LOG_DBG("Thread %d is inside library (RIP=0x%lx), detaching and will retry", tid, regs.rip);
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

void DL_Manager::cleanup_old_libraries(const std::string& target_lib_path,
                                        const std::string& new_lib_path,
                                        pid_t tid,
                                        struct user_regs_struct& saved_regs) {
    LOG_DBG("Cleaning up old libraries...");
    
    std::set<std::string> to_unload;
    for (const auto& pair : tracked_libraries_) {
        const TrackedLibrary& lib = pair.second;
        if (lib.path == new_lib_path) continue;
        if (lib.path == target_lib_path && lib.is_original) continue;
        if (!lib.is_active && !lib.is_original) {
            to_unload.insert(lib.path);
        }
    }
    
    for (const std::string& path : to_unload) {
        auto it = tracked_libraries_.find(path);
        if (it != tracked_libraries_.end() && it->second.handle != 0) {
            LOG_INFO("Unloading unused library: %s", path.c_str());
            if (unload_library_by_handle(tid, it->second.handle, saved_regs)) {
                tracked_libraries_.erase(it);
            } else {
                LOG_ERR("Failed to unload %s", path.c_str());
            }
        }
    }
}

bool DL_Manager::replace_library(const std::string& target_lib_pattern,
                                  const std::string& new_lib_path,
                                  const std::string& target_function) {
    LOG_INFO("=== Starting library replacement ===");
    LOG_INFO("Target pattern: %s", target_lib_pattern.c_str());
    LOG_INFO("New: %s", new_lib_path.c_str());
    LOG_INFO("Function: %s", target_function.c_str());

    if (dlopen_addr_ == 0 || dlclose_addr_ == 0 || syscall_insn_ == 0) {
        LOG_ERR("Required addresses not initialized");
        return false;
    }

    LibraryInfo target_info = get_library_info(target_lib_pattern);
    if (target_info.base_addr == 0) {
        LOG_ERR("Target library not found");
        return false;
    }

    if (new_lib_path == target_info.path) {
        LOG_INFO("New library is the same as target, nothing to do.");
        return true;
    }

    std::vector<pid_t> all_tids = get_all_threads(pid_);
    if (all_tids.empty()) {
        LOG_ERR("No threads found");
        return false;
    }

    const int MAX_ATTEMPTS = 50;
    const int RETRY_US = 10000;

    std::vector<ThreadContext> contexts;
    bool freeze_success = false;

    for (int attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
        if (!stop_all_threads(all_tids, contexts)) {
            return false;
        }

        if (all_threads_outside(contexts, target_info.segments)) {
            freeze_success = true;
            break;
        }

        restore_and_detach_all(contexts);
        contexts.clear();
        usleep(RETRY_US);
    }

    if (!freeze_success) {
        LOG_ERR("Failed to freeze all threads outside the library after %d attempts", MAX_ATTEMPTS);
        return false;
    }

    pid_t worker_tid = pid_;
    ThreadContext worker_ctx;
    bool found = false;
    for (const auto& ctx : contexts) {
        if (ctx.tid == worker_tid) {
            worker_ctx = ctx;
            found = true;
            break;
        }
    }
    if (!found) {
        worker_tid = contexts[0].tid;
        worker_ctx = contexts[0];
        LOG_INFO("Main thread not found, using thread %d for injection", worker_tid);
    }

    // Prepare worker thread for remote execution (bring it out of kernel)
    for (int i = 0; i < 2; ++i) {
        if (ptrace(PTRACE_SYSCALL, worker_tid, nullptr, nullptr) == -1) {
            LOG_ERR("ptrace SYSCALL failed during preparation");
            restore_and_detach_all(contexts);
            return false;
        }
        int status;
        waitpid(worker_tid, &status, 0);
        if (!WIFSTOPPED(status)) {
            LOG_ERR("Thread did not stop after PTRACE_SYSCALL (attempt %d)", i);
            restore_and_detach_all(contexts);
            return false;
        }
    }

    // After preparation, read the current registers (they might have changed)
    struct user_regs_struct prepared_regs;
    if (ptrace(PTRACE_GETREGS, worker_tid, nullptr, &prepared_regs) == -1) {
        LOG_ERR("Failed to get registers after preparation");
        restore_and_detach_all(contexts);
        return false;
    }

    LOG_INFO("Prepared RIP=0x%llx, RSP=0x%llx", (unsigned long long)prepared_regs.rip, 
             (unsigned long long)prepared_regs.rsp);

    // Verify that RSP points to a valid stack region
    std::string maps_path = "/proc/" + std::to_string(pid_) + "/maps";
    std::ifstream maps_file(maps_path);
    bool rsp_valid = false;
    if (maps_file.is_open()) {
        std::string line;
        while (std::getline(maps_file, line)) {
            if (line.find("[stack]") != std::string::npos) {
                size_t dash = line.find('-');
                if (dash != std::string::npos) {
                    uintptr_t start = std::stoull(line.substr(0, dash), nullptr, 16);
                    uintptr_t end = std::stoull(line.substr(dash + 1), nullptr, 16);
                    if (prepared_regs.rsp >= start && prepared_regs.rsp < end) {
                        rsp_valid = true;
                        break;
                    }
                }
            }
        }
        if (!rsp_valid) {
            // Check other RW regions that might be stacks
            maps_file.clear();
            maps_file.seekg(0);
            while (std::getline(maps_file, line)) {
                if (line.find("rw-p") != std::string::npos) {
                    size_t dash = line.find('-');
                    if (dash != std::string::npos) {
                        uintptr_t start = std::stoull(line.substr(0, dash), nullptr, 16);
                        uintptr_t end = std::stoull(line.substr(dash + 1), nullptr, 16);
                        if (prepared_regs.rsp >= start && prepared_regs.rsp < end) {
                            rsp_valid = true;
                            break;
                        }
                    }
                }
            }
        }
    }
    if (!rsp_valid) {
        LOG_WARN("RSP 0x%llx may not be in a valid stack region, injection might fail", 
                 (unsigned long long)prepared_regs.rsp);
    }

    // Use prepared_regs for injection, not the old saved_regs
    struct user_regs_struct saved_regs = prepared_regs;

    // Test syscall mechanism (this will use the prepared thread)
    if (!test_syscall(worker_tid)) {
        LOG_ERR("Syscall test failed");
        restore_and_detach_all(contexts);
        return false;
    }

    // Load the new library using the prepared registers
    uintptr_t new_lib_base = 0, new_handle = 0;
    if (!ensure_new_library_loaded(worker_tid, new_lib_path, new_lib_base, new_handle, saved_regs)) {
        LOG_ERR("Failed to load new library");
        restore_and_detach_all(contexts);
        return false;
    } 

    // Apply all patches
    bool patch_success = apply_all_patches(worker_tid, target_info.base_addr, new_lib_base,
                                           new_lib_path, target_function, saved_regs);

    if (patch_success) {
        // Update tracker: deactivate all other libraries, activate new one
        for (auto& pair : tracked_libraries_) {
            if (pair.first != new_lib_path) pair.second.is_active = false;
        }
        tracked_libraries_[new_lib_path].is_active = true;
        tracked_libraries_[new_lib_path].patched_libraries.push_back(target_info.path);

        // Mark target as original if not already tracked
        if (tracked_libraries_.find(target_info.path) == tracked_libraries_.end()) {
            TrackedLibrary target_lib(target_info.path, 0, target_info.base_addr, target_function);
            target_lib.is_original = true;
            tracked_libraries_[target_info.path] = target_lib;
            LOG_INFO("Added original library to tracker: %s", target_info.path.c_str());
        }

        // Clean up unused libraries
        cleanup_old_libraries(target_info.path, new_lib_path, worker_tid, saved_regs);
    }

    // Restore registers and detach all threads
    restore_and_detach_all(contexts);

    if (patch_success) {
        LOG_INFO("=== Library replacement completed successfully ===");
        return true;
    } else {
        LOG_ERR("=== Library replacement failed ===");
        return false;
    }
}
