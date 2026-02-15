// DL_manager_replace.ipp
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <iostream>
#include <dirent.h>
#include <cctype>
#include <fstream>
#include <sstream>

// Shellcode offsets (positions where we patch 64-bit addresses)
enum {
    SHELLCODE_PATH_OFFSET   = 2,
    SHELLCODE_DLOPEN_OFFSET = 16,
    SHELLCODE_RESULT_OFFSET = 33,
    SHELLCODE_DLERROR_OFFSET = 58,
    SHELLCODE_ERROR_OFFSET  = 70
};

// Manually crafted shellcode (x86-64)
static const unsigned char shellcode_template[] = {
    0x55,                               // push rbp
    0x48, 0x89, 0xe5,                   // mov rbp, rsp
    0x57,                               // push rdi
    0x56,                               // push rsi
    0x51,                               // push rcx
    0x41, 0x53,                         // push r11

    // mov rdi, path_addr
    0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // mov rsi, 2 (RTLD_NOW)
    0x48, 0xc7, 0xc6, 0x02, 0x00, 0x00, 0x00,

    // mov rax, dlopen_addr
    0x48, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // call rax
    0xff, 0xd0,

    // mov [result_addr], rax
    0x48, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // cmp rax, 0
    0x48, 0x83, 0xf8, 0x00,

    // jne done
    0x75, 0x1a,

    // mov rax, dlerror_addr
    0x48, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // call rax
    0xff, 0xd0,

    // mov [error_addr], rax
    0x48, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // done:
    0x41, 0x5b,                         // pop r11
    0x59,                               // pop rcx
    0x5e,                               // pop rsi
    0x5f,                               // pop rdi
    0x5d,                               // pop rbp
    0xcc,                               // int3
    0xc3                                // ret
};

// Helper: get all thread IDs
static std::vector<pid_t> get_all_threads(pid_t pid) {
    std::vector<pid_t> tids;
    char task_path[256];
    snprintf(task_path, sizeof(task_path), "/proc/%d/task", pid);
    DIR* dir = opendir(task_path);
    if (!dir) return tids;
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type == DT_DIR) {
            bool is_num = true;
            for (char* p = entry->d_name; *p; ++p) {
                if (!isdigit(*p)) { is_num = false; break; }
            }
            if (is_num) tids.push_back(atoi(entry->d_name));
        }
    }
    closedir(dir);
    return tids;
}

// Helper: stop all threads
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

// Helper: resume all threads
static void resume_all_threads(const std::vector<pid_t>& tids) {
    for (pid_t tid : tids) {
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
    }
}

// Helper: write remote memory
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

// Helper: read remote memory
static bool read_remote_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size) {
    struct iovec local = {buffer, size};
    struct iovec remote = {reinterpret_cast<void*>(addr), size};
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    return n == static_cast<ssize_t>(size);
}

// Execute a system call by hijacking the next one
static bool remote_syscall(pid_t pid, uintptr_t& result,
                           long number,
                           uintptr_t arg1, uintptr_t arg2,
                           uintptr_t arg3, uintptr_t arg4,
                           uintptr_t arg5, uintptr_t arg6) {
    // Wait for next syscall entry
    if (ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr) == -1) {
        perror("ptrace SYSCALL");
        return false;
    }

    int status;
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        std::cerr << "Unexpected stop at entry: signal=" << WSTOPSIG(status) << std::endl;
        return false;
    }

    // Save original registers
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
        perror("ptrace GETREGS");
        return false;
    }

    struct user_regs_struct saved_regs = regs;

    // Replace with our syscall
    regs.rax = number;
    regs.rdi = arg1;
    regs.rsi = arg2;
    regs.rdx = arg3;
    regs.r10 = arg4;
    regs.r8  = arg5;
    regs.r9  = arg6;

    if (ptrace(PTRACE_SETREGS, pid, nullptr, &regs) == -1) {
        perror("ptrace SETREGS");
        return false;
    }

    // Continue to exit
    if (ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr) == -1) {
        perror("ptrace SYSCALL exit");
        return false;
    }

    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        std::cerr << "Unexpected stop at exit: signal=" << WSTOPSIG(status) << std::endl;
        return false;
    }

    // Read result
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
        perror("ptrace GETREGS exit");
        return false;
    }
    result = regs.rax;

    // Restore original registers (so the process continues with its own syscall)
    if (ptrace(PTRACE_SETREGS, pid, nullptr, &saved_regs) == -1) {
        perror("ptrace SETREGS restore");
        return false;
    }

    return true;
}

// Remote mmap
static uintptr_t remote_mmap(pid_t pid, size_t length, int prot, int flags, int fd, off_t offset) {
    uintptr_t result;
    if (!remote_syscall(pid, result, 9, 0, length, prot, flags, fd, offset)) {
        return 0;
    }
    if (result == ~0ULL) {
        std::cerr << "remote mmap failed" << std::endl;
        return 0;
    }
    return result;
}

// Remote munmap
static bool remote_munmap(pid_t pid, uintptr_t addr, size_t length) {
    uintptr_t result;
    if (!remote_syscall(pid, result, 11, addr, length, 0, 0, 0, 0)) {
        return false;
    }
    if (result != 0) {
        std::cerr << "remote munmap failed" << std::endl;
        return false;
    }
    return true;
}

// Main method
bool DL_Manager::replace_library(const std::string& target_lib_pattern, const std::string& new_lib_path) {
    if (!is_safe_to_replace(target_lib_pattern)) {
        std::cerr << "Not safe to replace library: threads are using it" << std::endl;
        return false;
    }

    LibraryInfo target_info = get_library_info(target_lib_pattern);
    if (target_info.base_addr == 0) {
        std::cerr << "Target library not found" << std::endl;
        return false;
    }

    LibraryInfo libc_info = get_library_info("libc.so");
    if (libc_info.base_addr == 0) {
        std::cerr << "libc not found" << std::endl;
        return false;
    }

    uintptr_t dlopen_addr = get_symbol_address(libc_info.base_addr, "dlopen");
    uintptr_t dlerror_addr = get_symbol_address(libc_info.base_addr, "dlerror");

    if (dlopen_addr == 0 || dlerror_addr == 0) {
        std::cerr << "Failed to find dlopen/dlerror in libc" << std::endl;
        return false;
    }

    std::vector<pid_t> tids = get_all_threads(pid_);
    if (tids.empty()) {
        std::cerr << "No threads found" << std::endl;
        return false;
    }

    if (!stop_all_threads(tids)) {
        resume_all_threads(tids);
        return false;
    }

    size_t mem_size = 4096;
    uintptr_t remote_mem = remote_mmap(pid_, mem_size,
                                       PROT_READ | PROT_WRITE | PROT_EXEC,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (remote_mem == 0) {
        std::cerr << "Failed to allocate remote memory" << std::endl;
        resume_all_threads(tids);
        return false;
    }

    uintptr_t path_addr      = remote_mem;
    uintptr_t shellcode_addr = remote_mem + 256;
    uintptr_t result_addr    = remote_mem + 512;
    uintptr_t error_addr     = remote_mem + 520;

    if (!write_remote_memory(pid_, path_addr, new_lib_path.c_str(), new_lib_path.size() + 1)) {
        std::cerr << "Failed to write library path" << std::endl;
        remote_munmap(pid_, remote_mem, mem_size);
        resume_all_threads(tids);
        return false;
    }

    unsigned char shellcode[sizeof(shellcode_template)];
    memcpy(shellcode, shellcode_template, sizeof(shellcode_template));
    *reinterpret_cast<uintptr_t*>(shellcode + SHELLCODE_PATH_OFFSET)   = path_addr;
    *reinterpret_cast<uintptr_t*>(shellcode + SHELLCODE_DLOPEN_OFFSET) = dlopen_addr;
    *reinterpret_cast<uintptr_t*>(shellcode + SHELLCODE_RESULT_OFFSET) = result_addr;
    *reinterpret_cast<uintptr_t*>(shellcode + SHELLCODE_DLERROR_OFFSET) = dlerror_addr;
    *reinterpret_cast<uintptr_t*>(shellcode + SHELLCODE_ERROR_OFFSET)  = error_addr;

    if (!write_remote_memory(pid_, shellcode_addr, shellcode, sizeof(shellcode))) {
        std::cerr << "Failed to write shellcode" << std::endl;
        remote_munmap(pid_, remote_mem, mem_size);
        resume_all_threads(tids);
        return false;
    }

    pid_t exec_tid = pid_;
    struct user_regs_struct old_regs;
    if (ptrace(PTRACE_GETREGS, exec_tid, nullptr, &old_regs) == -1) {
        perror("ptrace GETREGS");
        remote_munmap(pid_, remote_mem, mem_size);
        resume_all_threads(tids);
        return false;
    }

    struct user_regs_struct new_regs = old_regs;
    new_regs.rip = shellcode_addr;
    new_regs.rsp -= 128;

    if (ptrace(PTRACE_SETREGS, exec_tid, nullptr, &new_regs) == -1) {
        perror("ptrace SETREGS");
        remote_munmap(pid_, remote_mem, mem_size);
        resume_all_threads(tids);
        return false;
    }

    if (ptrace(PTRACE_CONT, exec_tid, nullptr, nullptr) == -1) {
        perror("ptrace CONT");
    }

    int status;
    waitpid(exec_tid, &status, 0);
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        std::cerr << "Unexpected stop signal: " << WSTOPSIG(status) << std::endl;
        ptrace(PTRACE_SETREGS, exec_tid, nullptr, &old_regs);
        remote_munmap(pid_, remote_mem, mem_size);
        resume_all_threads(tids);
        return false;
    }

    uintptr_t handle = 0;
    if (!read_remote_memory(pid_, result_addr, &handle, sizeof(handle))) {
        std::cerr << "Failed to read result handle" << std::endl;
    }

    bool success = (handle != 0);
    if (success) {
        std::cout << "Library loaded successfully, handle = 0x" << std::hex << handle << std::dec << std::endl;
    } else {
        uintptr_t err_ptr = 0;
        if (read_remote_memory(pid_, error_addr, &err_ptr, sizeof(err_ptr)) && err_ptr != 0) {
            char err_buf[256] = {0};
            read_remote_memory(pid_, err_ptr, err_buf, sizeof(err_buf)-1);
            std::cerr << "dlopen error: " << err_buf << std::endl;
        } else {
            std::cerr << "dlopen failed (NULL handle)" << std::endl;
        }
    }

    ptrace(PTRACE_SETREGS, exec_tid, nullptr, &old_regs);
    remote_munmap(pid_, remote_mem, mem_size);
    resume_all_threads(tids);

    return success;
}
