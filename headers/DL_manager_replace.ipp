// DL_manager_replace.ipp – полная реализация с управлением несколькими библиотеками

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

// ============================================================================
// Basic ptrace helpers (assumed to be available from other files)
// ============================================================================
static std::vector<pid_t> get_all_threads(pid_t pid);
static bool stop_all_threads(const std::vector<pid_t>& tids);
static void resume_all_threads(const std::vector<pid_t>& tids);
static bool write_remote_memory(pid_t pid, uintptr_t addr, const void* data, size_t size);
static bool read_remote_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size);
static bool remote_syscall(pid_t pid, uintptr_t& result,
                           long number,
                           uintptr_t arg1, uintptr_t arg2,
                           uintptr_t arg3, uintptr_t arg4,
                           uintptr_t arg5, uintptr_t arg6,
                           uintptr_t syscall_insn_addr);
static uintptr_t remote_mmap(pid_t pid, size_t length, int prot, int flags, int fd, off_t offset,
                             uintptr_t syscall_insn_addr);
static bool remote_munmap(pid_t pid, uintptr_t addr, size_t length, uintptr_t syscall_insn_addr);


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
                if (!isdigit(*p)) {
                    is_number = false;
                    break;
                }
            }
            if (is_number) {
                tids.push_back(atoi(entry->d_name));
            }
        }
    }
    closedir(dir);

    std::sort(tids.begin(), tids.end());
    return tids;
}

static bool stop_all_threads(const std::vector<pid_t>& tids) {
    for (pid_t tid : tids) {
        if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == -1) {
            perror("ptrace ATTACH");
            return false;
        }
        int status;
        waitpid(tid, &status, 0);
        if (!WIFSTOPPED(status)) {
            std::cerr << "Thread " << tid << " did not stop" << std::endl;
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
            perror("ptrace POKEDATA");
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
        perror("ptrace GETREGS");
        return false;
    }

    struct user_regs_struct saved_regs = regs;

    // Set up registers for the system call
    regs.rax = number;
    regs.rdi = arg1;
    regs.rsi = arg2;
    regs.rdx = arg3;
    regs.r10 = arg4;  // on x86-64, 4th argument is in r10
    regs.r8  = arg5;
    regs.r9  = arg6;
    regs.rip = syscall_insn_addr;

    if (ptrace(PTRACE_SETREGS, pid, nullptr, &regs) == -1) {
        perror("ptrace SETREGS");
        return false;
    }

    // Single step to execute the syscall instruction
    if (ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr) == -1) {
        perror("ptrace SINGLESTEP");
        ptrace(PTRACE_SETREGS, pid, nullptr, &saved_regs);
        return false;
    }

    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
        std::cerr << "Process exited during syscall with status " << WEXITSTATUS(status) << std::endl;
        return false;
    }
    if (WIFSIGNALED(status)) {
        std::cerr << "Process killed by signal " << WTERMSIG(status) << std::endl;
        return false;
    }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        std::cerr << "Unexpected stop after syscall: signal=" << WSTOPSIG(status) << std::endl;
        ptrace(PTRACE_SETREGS, pid, nullptr, &saved_regs);
        return false;
    }

    // Read result from rax
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
        perror("ptrace GETREGS after syscall");
        ptrace(PTRACE_SETREGS, pid, nullptr, &saved_regs);
        return false;
    }
    result = regs.rax;

    // Restore original registers
    ptrace(PTRACE_SETREGS, pid, nullptr, &saved_regs);

    return true;
}

static uintptr_t remote_mmap(pid_t pid, size_t length, int prot, int flags, int fd, off_t offset,
                             uintptr_t syscall_insn_addr) {
    uintptr_t result;
    if (!remote_syscall(pid, result, 9, 0, length, prot, flags, fd, offset, syscall_insn_addr)) {
        return 0;
    }
    // mmap returns (void*)-1 on error, which is ~0ULL
    if (result == ~0ULL) {
        std::cerr << "remote mmap failed" << std::endl;
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
        std::cerr << "remote munmap failed" << std::endl;
        return false;
    }
    return true;
}

// ============================================================================
// Helper to check if library is still mapped
// ============================================================================
static bool is_library_mapped(pid_t pid, const std::string& lib_path) {
    std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream maps_file(maps_path);
    if (!maps_file.is_open()) return false;

    std::string line;
    while (std::getline(maps_file, line)) {
        if (line.find(lib_path) != std::string::npos) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// Force unload library by unmapping all its segments
// ============================================================================
static bool force_unload_library(pid_t pid, uintptr_t base_addr, size_t total_size,
                                  uintptr_t syscall_insn_addr) {
    // First try to unmap the entire region
    return remote_munmap(pid, base_addr, total_size, syscall_insn_addr);
}

// ============================================================================
// Initialization of required addresses from libc
// ============================================================================
void DL_Manager::init_addresses() {
    LibraryInfo libc_info = get_library_info("libc.so");
    if (libc_info.base_addr == 0) {
        std::cerr << "Warning: libc not found, some features may not work" << std::endl;
        return;
    }
    
    dlopen_addr_ = get_symbol_address(libc_info.base_addr, "dlopen");
    dlclose_addr_ = get_symbol_address(libc_info.base_addr, "dlclose");
    syscall_insn_ = find_syscall_instruction(libc_info.base_addr);
    
    std::cout << "Initialized addresses:" << std::endl;
    std::cout << "  dlopen  : 0x" << std::hex << dlopen_addr_ << std::dec << std::endl;
    std::cout << "  dlclose : 0x" << std::hex << dlclose_addr_ << std::dec << std::endl;
    std::cout << "  syscall : 0x" << std::hex << syscall_insn_ << std::dec << std::endl;
}

// ============================================================================
// Find real syscall instruction inside libc
// ============================================================================
uintptr_t DL_Manager::find_syscall_instruction(uintptr_t libc_base) {
    // First try to get the syscall function symbol
    uintptr_t syscall_func = get_symbol_address(libc_base, "syscall");
    if (syscall_func == 0) {
        std::cerr << "Failed to find syscall symbol" << std::endl;
        return 0;
    }
    
    // Read first 64 bytes of the function
    unsigned char buffer[64];
    if (!read_remote_memory(pid_, syscall_func, buffer, sizeof(buffer))) {
        std::cerr << "Failed to read syscall function" << std::endl;
        return 0;
    }
    
    // Look for 0x0f 0x05 (syscall instruction)
    for (int i = 0; i < (int)sizeof(buffer) - 1; ++i) {
        if (buffer[i] == 0x0f && buffer[i+1] == 0x05) {
            uintptr_t candidate = syscall_func + i;
            
            // Verify it's in an executable segment by reading /proc/pid/maps
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
                            std::cout << "Found syscall instruction at 0x" << std::hex << candidate << std::dec << std::endl;
                            return candidate;
                        }
                    }
                }
            }
        }
    }
    
    std::cerr << "No syscall instruction found in first 64 bytes" << std::endl;
    return 0;
}

// ============================================================================
// Check if library is already loaded and get its base address and handle
// ============================================================================
bool DL_Manager::is_library_already_loaded(const std::string& lib_path, uintptr_t& base_addr, uintptr_t& handle) {
    // First check tracked libraries (faster)
    auto it = tracked_libraries_.find(lib_path);
    if (it != tracked_libraries_.end()) {
        base_addr = it->second.base_addr;
        handle = it->second.handle;
        return true;
    }
    
    // If not tracked, check /proc/pid/maps
    std::string maps_path = "/proc/" + std::to_string(pid_) + "/maps";
    std::ifstream maps_file(maps_path);
    if (!maps_file.is_open()) return false;
    
    std::string line;
    while (std::getline(maps_file, line)) {
        if (line.find(lib_path) != std::string::npos) {
            size_t dash = line.find('-');
            if (dash != std::string::npos) {
                base_addr = std::stoul(line.substr(0, dash), nullptr, 16);
                // We don't know the handle for untracked libraries, set to 0
                handle = 0;
                return true;
            }
        }
    }
    
    return false;
}

// ============================================================================
// Test syscall mechanism with getpid
// ============================================================================
bool DL_Manager::test_syscall(pid_t tid) {
    if (syscall_insn_ == 0) return false;
    
    uintptr_t result;
    if (!remote_syscall(tid, result, 39, 0, 0, 0, 0, 0, 0, syscall_insn_)) {
        std::cerr << "Test syscall failed" << std::endl;
        return false;
    }
    
    std::cout << "Test getpid returned " << result << std::endl;
    return true;
}

// ============================================================================
// Stop all threads and prepare main thread for injection
// ============================================================================
std::vector<pid_t> DL_Manager::stop_threads_and_prepare_main(pid_t& main_tid, 
                                                              struct user_regs_struct& saved_regs) {
    std::vector<pid_t> tids = get_all_threads(pid_);
    if (tids.empty()) {
        std::cerr << "No threads found" << std::endl;
        return {};
    }
    
    if (!stop_all_threads(tids)) {
        resume_all_threads(tids);
        return {};
    }
    
    main_tid = pid_; // main thread ID is the process PID
    
    // Double PTRACE_SYSCALL to ensure thread is out of kernel space
    for (int i = 0; i < 2; ++i) {
        if (ptrace(PTRACE_SYSCALL, main_tid, nullptr, nullptr) == -1) {
            perror("ptrace SYSCALL");
            resume_all_threads(tids);
            return {};
        }
        int status;
        waitpid(main_tid, &status, 0);
        if (!WIFSTOPPED(status)) {
            std::cerr << "Thread did not stop after PTRACE_SYSCALL" << std::endl;
            resume_all_threads(tids);
            return {};
        }
    }
    std::cout << "Main thread is now in userspace" << std::endl;
    
    // Save original registers
    if (ptrace(PTRACE_GETREGS, main_tid, nullptr, &saved_regs) == -1) {
        perror("ptrace GETREGS");
        resume_all_threads(tids);
        return {};
    }
    
    return tids;
}

// ============================================================================
// Load new library using dlopen shellcode
// Returns base address of loaded library, and sets out_handle
// ============================================================================
uintptr_t DL_Manager::load_new_library(pid_t tid, const std::string& lib_path,
                                        uintptr_t& out_handle,
                                        struct user_regs_struct& saved_regs) {
    if (dlopen_addr_ == 0 || syscall_insn_ == 0) {
        std::cerr << "Required addresses not initialized" << std::endl;
        return 0;
    }
    
    // Allocate remote memory
    size_t mem_size = 4096;
    uintptr_t remote_mem = remote_mmap(tid, mem_size,
                                       PROT_READ | PROT_WRITE | PROT_EXEC,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0,
                                       syscall_insn_);
    if (remote_mem == 0) {
        std::cerr << "Failed to allocate remote memory" << std::endl;
        return 0;
    }
    
    uintptr_t shellcode_addr = remote_mem;
    uintptr_t path_addr      = remote_mem + 256;
    uintptr_t result_addr    = remote_mem + 512;
    
    // Write library path
    if (!write_remote_memory(pid_, path_addr, lib_path.c_str(), lib_path.size() + 1)) {
        std::cerr << "Failed to write library path" << std::endl;
        remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
        return 0;
    }
    
    // Shellcode: call dlopen, store result, int3
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
    
    // Patch addresses
    const size_t PATH_OFFSET = 9;
    const size_t DLOPEN_OFFSET = 26;
    const size_t RESULT_OFFSET = 38;
    *reinterpret_cast<uintptr_t*>(shellcode + PATH_OFFSET) = path_addr;
    *reinterpret_cast<uintptr_t*>(shellcode + DLOPEN_OFFSET) = dlopen_addr_;
    *reinterpret_cast<uintptr_t*>(shellcode + RESULT_OFFSET) = result_addr;
    
    // Write shellcode byte by byte with verification
    for (size_t i = 0; i < sizeof(shellcode); i++) {
        uintptr_t addr = shellcode_addr + i;
        unsigned char val = shellcode[i];
        if (!write_remote_memory(pid_, addr, &val, 1)) {
            std::cerr << "Failed to write byte at offset " << i << std::endl;
            remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
            return 0;
        }
        
        unsigned char verify = 0;
        if (!read_remote_memory(pid_, addr, &verify, 1) || verify != val) {
            std::cerr << "Verification failed at offset " << i << std::endl;
            remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
            return 0;
        }
    }
    std::cout << "Shellcode written and verified successfully" << std::endl;
    
    // Set RIP to shellcode
    struct user_regs_struct new_regs = saved_regs;
    new_regs.rip = shellcode_addr;
    if (ptrace(PTRACE_SETREGS, tid, nullptr, &new_regs) == -1) {
        perror("ptrace SETREGS");
        remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
        return 0;
    }
    
    // Execute
    if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) == -1) {
        perror("ptrace CONT");
    }
    
    int status;
    waitpid(tid, &status, 0);
    
    uintptr_t handle = 0;
    bool dlopen_ok = false;
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        if (read_remote_memory(pid_, result_addr, &handle, sizeof(handle)) && handle != 0) {
            std::cout << "dlopen succeeded, handle = 0x" << std::hex << handle << std::dec << std::endl;
            dlopen_ok = true;
            out_handle = handle;
        } else {
            std::cerr << "dlopen returned NULL" << std::endl;
        }
    } else {
        std::cerr << "Unexpected stop after shellcode: status=" << status << std::endl;
    }
    
    // Restore original registers
    ptrace(PTRACE_SETREGS, tid, nullptr, &saved_regs);
    
    if (!dlopen_ok) {
        remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
        return 0;
    }
    
    // Find base address of newly loaded library
    uintptr_t new_lib_base = 0;
    std::string maps_path = "/proc/" + std::to_string(pid_) + "/maps";
    std::ifstream maps_file(maps_path);
    if (maps_file.is_open()) {
        std::string line;
        while (std::getline(maps_file, line)) {
            if (line.find(lib_path) != std::string::npos) {
                size_t dash = line.find('-');
                if (dash != std::string::npos) {
                    new_lib_base = std::stoul(line.substr(0, dash), nullptr, 16);
                    break;
                }
            }
        }
    }
    
    if (new_lib_base == 0) {
        std::cerr << "Failed to find new library base in maps" << std::endl;
        remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
        return 0;
    }
    
    std::cout << "New library base at 0x" << std::hex << new_lib_base << std::dec << std::endl;
    
    // Clean up temporary memory
    remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
    
    return new_lib_base;
}

// ============================================================================
// Unload library by handle using dlclose
// ============================================================================
bool DL_Manager::unload_library_by_handle(pid_t tid, uintptr_t handle,
                                           struct user_regs_struct& saved_regs) {
    if (dlclose_addr_ == 0 || syscall_insn_ == 0) {
        std::cerr << "Required addresses not initialized" << std::endl;
        return false;
    }
    
    if (handle == 0) {
        std::cerr << "Invalid handle (0)" << std::endl;
        return false;
    }
    
    // Allocate small memory for unload shellcode
    size_t mem_size = 256;
    uintptr_t remote_mem = remote_mmap(tid, mem_size,
                                       PROT_READ | PROT_WRITE | PROT_EXEC,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0,
                                       syscall_insn_);
    if (remote_mem == 0) {
        std::cerr << "Failed to allocate remote memory for unload" << std::endl;
        return false;
    }
    
    uintptr_t shellcode_addr = remote_mem;
    
    // Shellcode: push registers, mov rdi, handle, call dlclose, int3
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
    
    // Patch addresses
    const size_t HANDLE_OFFSET = 9;
    const size_t DLCLOSE_OFFSET = 19;
    *reinterpret_cast<uintptr_t*>(shellcode + HANDLE_OFFSET) = handle;
    *reinterpret_cast<uintptr_t*>(shellcode + DLCLOSE_OFFSET) = dlclose_addr_;
    
    // Write shellcode
    for (size_t i = 0; i < sizeof(shellcode); ++i) {
        if (!write_remote_memory(pid_, shellcode_addr + i, &shellcode[i], 1)) {
            std::cerr << "Failed to write unload shellcode at offset " << i << std::endl;
            remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
            return false;
        }
    }
    
    // Set RIP to shellcode
    struct user_regs_struct new_regs = saved_regs;
    new_regs.rip = shellcode_addr;
    if (ptrace(PTRACE_SETREGS, tid, nullptr, &new_regs) == -1) {
        perror("ptrace SETREGS for unload");
        remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
        return false;
    }
    
    // Execute
    if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) == -1) {
        perror("ptrace CONT for unload");
    }
    
    int status;
    waitpid(tid, &status, 0);
    
    bool success = false;
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        std::cout << "dlclose completed successfully" << std::endl;
        success = true;
    } else {
        std::cerr << "Unexpected stop during unload: status=" << status << std::endl;
    }
    
    // Restore original registers
    ptrace(PTRACE_SETREGS, tid, nullptr, &saved_regs);
    
    // Clean up temporary memory
    remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
    
    return success;
}

// ============================================================================
// Apply jmp patch from old function to new function
// ============================================================================
bool DL_Manager::apply_patch(pid_t tid, uintptr_t old_func, uintptr_t new_func,
                              struct user_regs_struct& saved_regs) {
    // Calculate relative jump offset
    // jmp rel32: E9 + 4-byte offset = 5 bytes
    int32_t rel32 = static_cast<int32_t>(new_func - (old_func + 5));
    unsigned char patch[5] = {0xE9, 0, 0, 0, 0};
    memcpy(patch + 1, &rel32, 4);
    
    // Write patch
    if (!write_remote_memory(pid_, old_func, patch, 5)) {
        std::cerr << "Failed to write patch at old function" << std::endl;
        return false;
    }
    
    // Verify
    unsigned char verify[5];
    if (!read_remote_memory(pid_, old_func, verify, 5)) {
        std::cerr << "Failed to read back patch for verification" << std::endl;
        return false;
    }
    
    if (memcmp(verify, patch, 5) != 0) {
        std::cerr << "Patch verification failed" << std::endl;
        return false;
    }
    
    std::cout << "Patch applied successfully: old_func(0x" << std::hex << old_func 
              << ") -> new_func(0x" << new_func << std::dec << ")" << std::endl;
    return true;
}

// ============================================================================
// Clean up old libraries that are no longer needed
// ============================================================================
void DL_Manager::cleanup_old_libraries(const std::string& target_lib_path,
                                        const std::string& new_lib_path,
                                        pid_t tid,
                                        struct user_regs_struct& saved_regs) {
    std::cout << "Cleaning up old libraries..." << std::endl;
    
    // Find all libraries that were patched to point to the new library
    // But we want to unload those that are no longer reachable
    std::set<std::string> to_unload;
    
    for (const auto& pair : tracked_libraries_) {
        const TrackedLibrary& lib = pair.second;
        
        // Skip the new library itself
        if (lib.path == new_lib_path) continue;
        
        // Skip the target library if it's the original (we keep original)
        if (lib.path == target_lib_path && lib.is_original) continue;
        
        // If this library is not active and not original, it can be unloaded
        if (!lib.is_active && !lib.is_original) {
            to_unload.insert(lib.path);
        }
    }
    
    // Also unload any library that has no incoming patches and is not the new one
    // (This is a simplified approach - in a real system you'd need reference counting)
    
    for (const std::string& path : to_unload) {
        auto it = tracked_libraries_.find(path);
        if (it != tracked_libraries_.end() && it->second.handle != 0) {
            std::cout << "Unloading unused library: " << path << std::endl;
            if (unload_library_by_handle(tid, it->second.handle, saved_regs)) {
                tracked_libraries_.erase(it);
            } else {
                std::cerr << "Failed to unload " << path << std::endl;
            }
        }
    }
}

// ============================================================================
// Print current library tracker state
// ============================================================================
void DL_Manager::print_library_tracker() const {
    std::cout << "\n=== Library Tracker Status ===" << std::endl;
    std::cout << "Tracked libraries: " << tracked_libraries_.size() << std::endl;
    
    for (const auto& pair : tracked_libraries_) {
        const TrackedLibrary& lib = pair.second;
        std::cout << "  Path: " << lib.path << std::endl;
        std::cout << "    Handle   : 0x" << std::hex << lib.handle << std::dec << std::endl;
        std::cout << "    Base     : 0x" << std::hex << lib.base_addr << std::dec << std::endl;
        std::cout << "    Function : " << lib.target_function << std::endl;
        std::cout << "    Active   : " << (lib.is_active ? "yes" : "no") << std::endl;
        std::cout << "    Original : " << (lib.is_original ? "yes" : "no") << std::endl;
        std::cout << "    Patched libs: " << lib.patched_libraries.size() << std::endl;
    }
    std::cout << "==============================\n" << std::endl;
}

// ============================================================================
// Public method to unload a specific library by path
// ============================================================================
bool DL_Manager::unload_library(const std::string& lib_path) {
    auto it = tracked_libraries_.find(lib_path);
    if (it == tracked_libraries_.end()) {
        std::cerr << "Library " << lib_path << " not found in tracker" << std::endl;
        return false;
    }
    
    TrackedLibrary& lib = it->second;
    
    // Don't unload active or original libraries
    if (lib.is_active) {
        std::cerr << "Cannot unload active library" << std::endl;
        return false;
    }
    
    if (lib.is_original) {
        std::cerr << "Cannot unload original library" << std::endl;
        return false;
    }
    
    // Stop threads
    struct user_regs_struct saved_regs;
    pid_t main_tid;
    std::vector<pid_t> tids = stop_threads_and_prepare_main(main_tid, saved_regs);
    if (tids.empty()) return false;
    
    bool result = unload_library_by_handle(main_tid, lib.handle, saved_regs);
    
    if (result) {
        tracked_libraries_.erase(it);
    }
    
    resume_all_threads(tids);
    return result;
}

// ============================================================================
// Main replace_library method
// ============================================================================
bool DL_Manager::replace_library(const std::string& target_lib_pattern,
                                  const std::string& new_lib_path,
                                  const std::string& target_function) {
    std::cout << "\n=== Starting library replacement ===" << std::endl;
    std::cout << "Target: " << target_lib_pattern << std::endl;
    std::cout << "New: " << new_lib_path << std::endl;
    std::cout << "Function: " << target_function << std::endl;
    
    // 1. Safety check
    if (!is_safe_to_replace(target_lib_pattern)) {
        std::cerr << "Not safe to replace library: threads are using it" << std::endl;
        return false;
    }
    
    // 2. Get target library info
    LibraryInfo target_info = get_library_info(target_lib_pattern);
    if (target_info.base_addr == 0) {
        std::cerr << "Target library not found" << std::endl;
        return false;
    }
    
    // 3. If same path, nothing to do
    if (new_lib_path == target_info.path) {
        std::cout << "New library is the same as target, nothing to do." << std::endl;
        return true;
    }
    
    // 4. Check if required addresses are initialized
    if (dlopen_addr_ == 0 || dlclose_addr_ == 0 || syscall_insn_ == 0) {
        std::cerr << "Required addresses not initialized. Call init_addresses() first." << std::endl;
        return false;
    }
    
    // 5. Stop all threads and prepare main thread
    struct user_regs_struct saved_regs;
    pid_t main_tid;
    std::vector<pid_t> tids = stop_threads_and_prepare_main(main_tid, saved_regs);
    if (tids.empty()) return false;
    
    // 6. Test syscall mechanism
    if (!test_syscall(main_tid)) {
        resume_all_threads(tids);
        return false;
    }
    
    // 7. Check if new library is already loaded and tracked
    uintptr_t new_lib_base = 0;
    uintptr_t new_handle = 0;
    bool already_loaded = is_library_already_loaded(new_lib_path, new_lib_base, new_handle);
    
    if (!already_loaded) {
        // Load the new library
        new_lib_base = load_new_library(main_tid, new_lib_path, new_handle, saved_regs);
        if (new_lib_base == 0) {
            resume_all_threads(tids);
            return false;
        }
        
        // Add to tracker
        TrackedLibrary new_lib(new_lib_path, new_handle, new_lib_base, target_function);
        tracked_libraries_[new_lib_path] = new_lib;
    } else {
        std::cout << "Library already loaded, using existing copy." << std::endl;
    }
    
    // 8. Get function addresses
    uintptr_t old_func = get_symbol_address(target_info.base_addr, target_function);
    uintptr_t new_func = get_symbol_address(new_lib_base, target_function);
    
    if (old_func == 0 || new_func == 0) {
        std::cerr << "Failed to find target function in libraries" << std::endl;
        resume_all_threads(tids);
        return false;
    }
    
    std::cout << "Old function at 0x" << std::hex << old_func << std::dec << std::endl;
    std::cout << "New function at 0x" << std::hex << new_func << std::dec << std::endl;
    
    // 9. Apply patch if addresses differ
    bool patch_success = true;
    if (old_func == new_func) {
        std::cout << "Function addresses are identical, no patch needed." << std::endl;
    } else {
        patch_success = apply_patch(main_tid, old_func, new_func, saved_regs);
    }
    
    if (patch_success) {
        // 10. Deactivate all libraries except the new one
        for (auto& pair : tracked_libraries_) {
            if (pair.first != new_lib_path) {
                pair.second.is_active = false;
            }
        }
        
        // Mark the new library as active
        tracked_libraries_[new_lib_path].is_active = true;
        tracked_libraries_[new_lib_path].patched_libraries.push_back(target_info.path);
        
        // Mark the target as original if not already
        if (tracked_libraries_.find(target_info.path) == tracked_libraries_.end()) {
            TrackedLibrary target_lib(target_info.path, 0, target_info.base_addr, target_function);
            target_lib.is_original = true;
            tracked_libraries_[target_info.path] = target_lib;
        }
        
        // 11. Clean up old unused libraries
        cleanup_old_libraries(target_info.path, new_lib_path, main_tid, saved_regs);
    }
    
    // 12. Resume all threads
    resume_all_threads(tids);
    
    std::cout << "=== Library replacement completed " 
              << (patch_success ? "successfully" : "with errors") << " ===\n" << std::endl;
    
    return patch_success;
}
