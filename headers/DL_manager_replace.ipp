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

// Constants
static const size_t REMOTE_MEM_SIZE = 4096;
static const size_t SHELLCODE_PATH_OFFSET = 256;
static const size_t SHELLCODE_RESULT_OFFSET = 512;

// Basic ptrace helpers
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

static bool stop_all_threads(const std::vector<pid_t>& tids) {
    for (pid_t tid : tids) {
        if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == -1) {
            LOG_ERR("ptrace ATTACH failed for thread %d", tid);
            return false;
        }
        int status;
        waitpid(tid, &status, 0);
        if (!WIFSTOPPED(status)) {
            LOG_ERR("Thread %d did not stop", tid);
            return false;
        }
    }
    return true;
}

static void resume_all_threads(const std::vector<pid_t>& tids) {
    for (pid_t tid : tids) {
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
    }
}

static bool write_remote_memory(pid_t pid, uintptr_t addr, const void* data, size_t size) {
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < size; i += sizeof(long)) {
        size_t chunk = std::min(sizeof(long), size - i);
        long word = 0;
        memcpy(&word, bytes + i, chunk);
        if (ptrace(PTRACE_POKEDATA, pid, addr + i, word) == -1) {
            LOG_ERR("ptrace POKEDATA failed at 0x%lx", addr + i);
            return false;
        }
    }
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
    
    if (!stop_all_threads(tids)) {
        resume_all_threads(tids);
        return {};
    }
    
    main_tid = pid_;
    for (int i = 0; i < 2; ++i) {
        if (ptrace(PTRACE_SYSCALL, main_tid, nullptr, nullptr) == -1) {
            LOG_ERR("ptrace SYSCALL failed");
            resume_all_threads(tids);
            return {};
        }
        int status;
        waitpid(main_tid, &status, 0);
        if (!WIFSTOPPED(status)) {
            LOG_ERR("Thread did not stop after PTRACE_SYSCALL");
            resume_all_threads(tids);
            return {};
        }
    }
    LOG_DBG("Main thread is now in userspace");
    
    if (ptrace(PTRACE_GETREGS, main_tid, nullptr, &saved_regs) == -1) {
        LOG_ERR("ptrace GETREGS failed");
        resume_all_threads(tids);
        return {};
    }
    
    return tids;
}

// ----------------------------------------------------------------------------
// Helper methods for load_new_library
// ----------------------------------------------------------------------------
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
        0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rdi, path_addr
        0x48, 0xc7, 0xc6, 0x02, 0x00, 0x00, 0x00,                    // mov rsi, 2 (RTLD_NOW)
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, dlopen_addr
        0xff, 0xd0,                                                    // call rax
        0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rdi, result_addr
        0x48, 0x89, 0x07,                                              // mov [rdi], rax
        0x58,                                                          // pop rax
        0x5e,                                                          // pop rsi
        0x5f,                                                          // pop rdi
        0x5d,                                                          // pop rbp
        0xcc,                                                          // int3
        0xc3                                                           // ret
    };
    
    const size_t PATH_OFFSET = 9;
    const size_t DLOPEN_OFFSET = 26;
    const size_t RESULT_OFFSET = 38;
    *reinterpret_cast<uintptr_t*>(shellcode + PATH_OFFSET) = path_addr;
    *reinterpret_cast<uintptr_t*>(shellcode + DLOPEN_OFFSET) = dlopen_addr_;
    *reinterpret_cast<uintptr_t*>(shellcode + RESULT_OFFSET) = result_addr;
    
    for (size_t i = 0; i < sizeof(shellcode); i++) {
        if (!write_remote_memory(tid, shellcode_addr + i, &shellcode[i], 1)) {
            LOG_ERR("Failed to write byte at offset %zu", i);
            return false;
        }
#ifdef DEBUG
        unsigned char verify = 0;
        if (!read_remote_memory(tid, shellcode_addr + i, &verify, 1) || verify != shellcode[i]) {
            LOG_ERR("Verification failed at offset %zu", i);
            return false;
        }
#endif
    }
    LOG_DBG("Shellcode written and verified");
    return true;
}

bool DL_Manager::execute_shellcode_and_get_handle(pid_t tid, uintptr_t shellcode_addr,
                                                   struct user_regs_struct& saved_regs,
                                                   uintptr_t& out_handle) {
    struct user_regs_struct new_regs = saved_regs;
    new_regs.rip = shellcode_addr;
    if (ptrace(PTRACE_SETREGS, tid, nullptr, &new_regs) == -1) {
        LOG_ERR("ptrace SETREGS failed");
        return false;
    }
    
    if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) == -1) {
        LOG_ERR("ptrace CONT failed");
        return false;
    }
    
    int status;
    waitpid(tid, &status, 0);
    
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        LOG_ERR("Unexpected stop after shellcode: status=%d", status);
        ptrace(PTRACE_SETREGS, tid, nullptr, &saved_regs);
        return false;
    }
    
    uintptr_t handle = 0;
    uintptr_t result_addr = shellcode_addr + SHELLCODE_RESULT_OFFSET;
    if (!read_remote_memory(pid_, result_addr, &handle, sizeof(handle)) || handle == 0) {
        LOG_ERR("dlopen returned NULL or read failed");
        ptrace(PTRACE_SETREGS, tid, nullptr, &saved_regs);
        return false;
    }
    
    out_handle = handle;
    LOG_DBG("dlopen succeeded, handle=0x%lx", handle);
    
    ptrace(PTRACE_SETREGS, tid, nullptr, &saved_regs);
    return true;
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
    
    uintptr_t remote_mem = allocate_remote_memory(tid, REMOTE_MEM_SIZE);
    if (remote_mem == 0) return 0;
    
    uintptr_t path_addr = remote_mem + SHELLCODE_PATH_OFFSET;
    uintptr_t result_addr = remote_mem + SHELLCODE_RESULT_OFFSET;
    
    if (!write_remote_memory(pid_, path_addr, lib_path.c_str(), lib_path.size() + 1)) {
        LOG_ERR("Failed to write library path");
        remote_munmap(pid_, remote_mem, REMOTE_MEM_SIZE, syscall_insn_);
        return 0;
    }
    
    if (!write_shellcode_with_verification(tid, remote_mem, path_addr, result_addr)) {
        remote_munmap(pid_, remote_mem, REMOTE_MEM_SIZE, syscall_insn_);
        return 0;
    }
    
    if (!execute_shellcode_and_get_handle(tid, remote_mem, saved_regs, out_handle)) {
        remote_munmap(pid_, remote_mem, REMOTE_MEM_SIZE, syscall_insn_);
        return 0;
    }
    
    uintptr_t new_lib_base = get_loaded_library_base(lib_path);
    if (new_lib_base == 0) {
        LOG_ERR("Failed to find new library base in maps");
        remote_munmap(pid_, remote_mem, REMOTE_MEM_SIZE, syscall_insn_);
        return 0;
    }
    
    LOG_INFO("New library loaded: base=0x%lx, handle=0x%lx", new_lib_base, out_handle);
    remote_munmap(pid_, remote_mem, REMOTE_MEM_SIZE, syscall_insn_);
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
        0x56,                               // push rsi
        0x50,                               // push rax
        0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rdi, handle
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, dlclose_addr
        0xff, 0xd0,                                                    // call rax
        0x58,                                                          // pop rax
        0x5e,                                                          // pop rsi
        0x5f,                                                          // pop rdi
        0x5d,                                                          // pop rbp
        0xcc,                                                          // int3
        0xc3                                                           // ret
    };
    
    const size_t HANDLE_OFFSET = 9;
    const size_t DLCLOSE_OFFSET = 19;
    *reinterpret_cast<uintptr_t*>(shellcode + HANDLE_OFFSET) = handle;
    *reinterpret_cast<uintptr_t*>(shellcode + DLCLOSE_OFFSET) = dlclose_addr_;
    
    for (size_t i = 0; i < sizeof(shellcode); ++i) {
        if (!write_remote_memory(pid_, remote_mem + i, &shellcode[i], 1)) {
            LOG_ERR("Failed to write unload shellcode at offset %zu", i);
            remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
            return false;
        }
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
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        LOG_DBG("dlclose completed successfully");
        success = true;
    } else {
        LOG_ERR("Unexpected stop during unload: status=%d", status);
    }
    
    ptrace(PTRACE_SETREGS, tid, nullptr, &saved_regs);
    remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
    return success;
}

bool DL_Manager::apply_patch(pid_t /*tid*/, uintptr_t old_func, uintptr_t new_func,
                              struct user_regs_struct& /*saved_regs*/) {
    int32_t rel32 = static_cast<int32_t>(new_func - (old_func + 5));
    unsigned char patch[5] = {0xE9, 0, 0, 0, 0};
    memcpy(patch + 1, &rel32, 4);
    
    if (!write_remote_memory(pid_, old_func, patch, 5)) {
        LOG_ERR("Failed to write patch at old function 0x%lx", old_func);
        return false;
    }
    
#ifdef DEBUG
    unsigned char verify[5];
    if (!read_remote_memory(pid_, old_func, verify, 5)) {
        LOG_ERR("Failed to read back patch for verification");
        return false;
    }
    if (memcmp(verify, patch, 5) != 0) {
        LOG_ERR("Patch verification failed at 0x%lx", old_func);
        return false;
    }
    LOG_DBG("Patch verified at 0x%lx", old_func);
#endif

    LOG_INFO("Patch applied: 0x%lx -> 0x%lx", old_func, new_func);
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
    std::vector<pid_t> tids = stop_threads_and_prepare_main(main_tid, saved_regs);
    if (tids.empty()) return false;
    
    bool result = unload_library_by_handle(main_tid, lib.handle, saved_regs);
    if (result) tracked_libraries_.erase(it);
    
    resume_all_threads(tids);
    return result;
}

// ----------------------------------------------------------------------------
// Patch application (all functions or single)
// ----------------------------------------------------------------------------
bool DL_Manager::apply_all_patches(pid_t tid, uintptr_t old_base, uintptr_t new_base,
                                     const std::string& new_lib_path,
                                     const std::string& target_function,
                                     struct user_regs_struct& saved_regs) {
    bool all_success = true;
    
    if (target_function == "all") {
        auto old_functions = get_function_symbols(old_base);
        LOG_INFO("Found %zu functions in old library", old_functions.size());
        
        std::vector<std::string> patched_functions;
        
        for (const auto& func_pair : old_functions) {
            const std::string& func_name = func_pair.first;
            uintptr_t old_func_addr = func_pair.second;
            uintptr_t new_func_addr = get_symbol_address(new_base, func_name);
            if (new_func_addr == 0) {
                LOG_WARN("Function '%s' not found in new library, skipping", func_name.c_str());
                continue;
            }
            
            if (old_func_addr != new_func_addr) {
                LOG_DBG("Patching %s: 0x%lx -> 0x%lx", func_name.c_str(), old_func_addr, new_func_addr);
                if (apply_patch(tid, old_func_addr, new_func_addr, saved_regs)) {
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
        
        LOG_DBG("Target function at 0x%lx, new at 0x%lx", old_func, new_func);
        
        if (old_func != new_func) {
            all_success = apply_patch(tid, old_func, new_func, saved_regs);
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

// ----------------------------------------------------------------------------
// Helper methods for replace_library (preconditions, loading, patching)
// ----------------------------------------------------------------------------
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

bool DL_Manager::ensure_new_library_loaded(pid_t main_tid, const std::string& new_lib_path,
                                           uintptr_t& new_lib_base, uintptr_t& new_handle,
                                           struct user_regs_struct& saved_regs) {
    bool already_loaded = is_library_already_loaded(new_lib_path, new_lib_base, new_handle);
    if (!already_loaded) {
        new_lib_base = load_new_library(main_tid, new_lib_path, new_handle, saved_regs);
        if (new_lib_base == 0) return false;
        
        tracked_libraries_[new_lib_path] = TrackedLibrary(new_lib_path, new_handle, new_lib_base, "");
        LOG_INFO("New library added to tracker");
    } else {
        LOG_INFO("Library already loaded, using existing copy.");
    }
    return true;
}

bool DL_Manager::apply_patches_and_update_tracker(pid_t main_tid, uintptr_t target_base, uintptr_t new_base,
                                                  const std::string& new_lib_path, const std::string& target_func,
                                                  struct user_regs_struct& saved_regs) {
    bool patch_success = apply_all_patches(main_tid, target_base, new_base,
                                           new_lib_path, target_func, saved_regs);
    if (!patch_success) return false;
    
    // Deactivate all libraries except the new one
    for (auto& pair : tracked_libraries_) {
        if (pair.first != new_lib_path) pair.second.is_active = false;
    }
    tracked_libraries_[new_lib_path].is_active = true;
    tracked_libraries_[new_lib_path].patched_libraries.push_back(target_func == "all" ? "all" : target_func);
    
    // Mark target as original if not already tracked
    LibraryInfo target_info = get_library_info(target_func); // actually we need target library path, but target_func is misleading. FIXME: pass target library path separately.
    // In replace_library we have target_lib_pattern, which is a pattern, not necessarily full path. But we can get path from target_info.path.
    // This part is tricky; we need to pass target_lib_path.
    // We'll fix in the main replace_library.
    
    return true;
}

// ----------------------------------------------------------------------------
// Main replace_library method
// ----------------------------------------------------------------------------
bool DL_Manager::replace_library(const std::string& target_lib_pattern,
                                  const std::string& new_lib_path,
                                  const std::string& target_function) {
    LOG_INFO("=== Starting library replacement ===");
    LOG_INFO("Target pattern: %s", target_lib_pattern.c_str());
    LOG_INFO("New: %s", new_lib_path.c_str());
    LOG_INFO("Function: %s", target_function.c_str());
    
    // 1. Preconditions
   if (!check_preconditions(target_lib_pattern)) return false; 

    // 2. Get target library info (full path, base)
    LibraryInfo target_info = get_library_info(target_lib_pattern);
    if (target_info.base_addr == 0) {
        LOG_ERR("Target library not found");
        return false;
    }
    
    // 3. If same path, nothing to do
    if (new_lib_path == target_info.path) {
        LOG_INFO("New library is the same as target, nothing to do.");
        return true;
    }
    
    // 4. Stop all threads and prepare main thread
    struct user_regs_struct saved_regs;
    pid_t main_tid;
    std::vector<pid_t> tids = stop_threads_and_prepare_main(main_tid, saved_regs);
    if (tids.empty()) return false;
    
    // 5. Test syscall mechanism (critical)
    if (!test_syscall(main_tid)) {
        resume_all_threads(tids);
        return false;
    }
    
    // 6. Ensure new library is loaded
    uintptr_t new_lib_base = 0, new_handle = 0;
    if (!ensure_new_library_loaded(main_tid, new_lib_path, new_lib_base, new_handle, saved_regs)) {
        resume_all_threads(tids);
        return false;
    }
    
    // 7. Apply patches
    bool patch_success = apply_all_patches(main_tid, target_info.base_addr, new_lib_base,
                                           new_lib_path, target_function, saved_regs);
    
    if (patch_success) {
        // Update tracker: deactivate others, activate new, mark target as original
        for (auto& pair : tracked_libraries_) {
            if (pair.first != new_lib_path) pair.second.is_active = false;
        }
        tracked_libraries_[new_lib_path].is_active = true;
        tracked_libraries_[new_lib_path].patched_libraries.push_back(target_info.path);
        
        if (tracked_libraries_.find(target_info.path) == tracked_libraries_.end()) {
            TrackedLibrary target_lib(target_info.path, 0, target_info.base_addr, target_function);
            target_lib.is_original = true;
            tracked_libraries_[target_info.path] = target_lib;
            LOG_INFO("Added original library to tracker: %s", target_info.path.c_str());
        }
        
        // 8. Clean up old unused libraries
        cleanup_old_libraries(target_info.path, new_lib_path, main_tid, saved_regs);
    }
    
    // 9. Resume all threads
    resume_all_threads(tids);
    
    LOG_INFO("=== Library replacement completed %s ===",
             patch_success ? "successfully" : "with errors");
    return patch_success;
}
