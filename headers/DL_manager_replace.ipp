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
static uintptr_t find_syscall_instruction(pid_t pid, DL_Manager* manager, uintptr_t libc_base);

static const unsigned char shellcode_template[] = {
    // Store registers
    0x50,                               // push rax
    0x51,                               // push rcx
    0x52,                               // push rdx
    0x53,                               // push rbx
    0x54,                               // push rsp
    0x55,                               // push rbp
    0x56,                               // push rsi
    0x57,                               // push rdi
    0x41, 0x50,                         // push r8
    0x41, 0x51,                         // push r9
    0x41, 0x52,                         // push r10
    0x41, 0x53,                         // push r11
    0x41, 0x54,                         // push r12
    0x41, 0x55,                         // push r13
    0x41, 0x56,                         // push r14
    0x41, 0x57,                         // push r15

    // mov rdi, path_addr
    0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // mov rsi, 2 (RTLD_NOW)
    0x48, 0xc7, 0xc6, 0x02, 0x00, 0x00, 0x00,

    // mov rax, dlopen_addr
    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // call rax
    0xff, 0xd0,

    // mov [result_addr], rax
    0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rdi, result_addr
    0x48, 0x89, 0x07,                                              // mov [rdi], rax

    // cmp rax, 0
    0x48, 0x85, 0xc0,                                              // test rax, rax
    0x74, 0x16,                                                    // jz error

    // restore registers and return
    0x41, 0x5f,                         // pop r15
    0x41, 0x5e,                         // pop r14
    0x41, 0x5d,                         // pop r13
    0x41, 0x5c,                         // pop r12
    0x41, 0x5b,                         // pop r11
    0x41, 0x5a,                         // pop r10
    0x41, 0x59,                         // pop r9
    0x41, 0x58,                         // pop r8
    0x5f,                               // pop rdi
    0x5e,                               // pop rsi
    0x5d,                               // pop rbp
    0x5c,                               // pop rsp
    0x5b,                               // pop rbx
    0x5a,                               // pop rdx
    0x59,                               // pop rcx
    0x58,                               // pop rax
    0xcc,                               // int3
    0xc3,                               // ret

    // error: call dlerror
    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, dlerror_addr
    0xff, 0xd0,                                                    // call rax
    0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rdi, error_addr
    0x48, 0x89, 0x07,                                              // mov [rdi], rax
    0xeb, 0xb8                                                     // jmp to restore (back to pop r15)
};

enum {
    SHELLCODE_PATH_OFFSET   = 30,    // mov rdi, path_addr
    SHELLCODE_DLOPEN_OFFSET = 47,    // mov rax, dlopen_addr
    SHELLCODE_RESULT_OFFSET = 63,    // mov rdi, result_addr (and store)
    SHELLCODE_DLERROR_OFFSET = 120,  // mov rax, dlerror_addr
    SHELLCODE_ERROR_OFFSET  = 134    // mov rdi, error_addr
};

static bool is_address_executable(pid_t pid, uintptr_t addr) {
    std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream file(maps_path);
    if (!file.is_open()) return false;
    std::string line;
    while (std::getline(file, line)) {
        size_t dash = line.find('-');
        if (dash == std::string::npos) continue;
        uintptr_t start = std::stoul(line.substr(0, dash), nullptr, 16);
        size_t space = line.find(' ', dash);
        if (space == std::string::npos) continue;
        uintptr_t end = std::stoul(line.substr(dash + 1, space - dash - 1), nullptr, 16);
        if (addr >= start && addr < end) {
            size_t perms_start = space + 1;
            size_t perms_end = line.find(' ', perms_start);
            std::string perms = line.substr(perms_start, perms_end - perms_start);
            if (perms.find('x') != std::string::npos) {
                return true;
            }
        }
    }
    return false;
}



// Helper: get all thread IDs of a process
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

// Helper: stop all threads via ptrace
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

// Helper: resume all threads (detach)
static void resume_all_threads(const std::vector<pid_t>& tids) {
    for (pid_t tid : tids) {
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
    }
}

// Helper: write memory using ptrace (word-aligned)
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

// Helper: read memory using process_vm_readv (efficient)
static bool read_remote_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size) {
    struct iovec local = {buffer, size};
    struct iovec remote = {reinterpret_cast<void*>(addr), size};
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    return n == static_cast<ssize_t>(size);
}

// Новая функция: находит реальный адрес инструкции syscall в libc
static uintptr_t find_syscall_instruction(pid_t pid, DL_Manager* manager, uintptr_t libc_base) {
    // 1. Получаем адрес функции syscall через символ
    uintptr_t syscall_func = manager->get_symbol_address(libc_base, "syscall");
    if (syscall_func == 0) {
        std::cerr << "Failed to find syscall symbol in libc" << std::endl;
        return 0;
    }

    // 2. Читаем первые 64 байта функции
    unsigned char buffer[64];
    if (!read_remote_memory(pid, syscall_func, buffer, sizeof(buffer))) {
        std::cerr << "Failed to read memory at syscall function" << std::endl;
        return 0;
    }

    // 3. Ищем последовательность 0x0f 0x05 (инструкция syscall)
    for (int i = 0; i < (int)sizeof(buffer) - 1; ++i) {
        if (buffer[i] == 0x0f && buffer[i+1] == 0x05) {
            uintptr_t candidate = syscall_func + i;
            if (is_address_executable(pid, candidate)) {
                std::cout << "Found syscall instruction at 0x" << std::hex << candidate << std::dec << std::endl;
                return candidate;
            }
        }
    }

    // 4. Если не нашли, можно расширить поиск (но в современных glibc syscall есть в начале)
    std::cerr << "No syscall instruction found within first 64 bytes of syscall function" << std::endl;
    return 0;
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

    // Устанавливаем аргументы системного вызова
    regs.rax = number;
    regs.rdi = arg1;
    regs.rsi = arg2;
    regs.rdx = arg3;
    regs.r10 = arg4;  // четвёртый аргумент
    regs.r8  = arg5;
    regs.r9  = arg6;
    regs.rip = syscall_insn_addr;

    if (ptrace(PTRACE_SETREGS, pid, nullptr, &regs) == -1) {
        perror("ptrace SETREGS");
        return false;
    }

    // Выполняем одну инструкцию (syscall)
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
        // Всё равно пытаемся восстановить регистры, но потом вернём false
        ptrace(PTRACE_SETREGS, pid, nullptr, &saved_regs);
        return false;
    }

    // Читаем результат (rax)
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
        perror("ptrace GETREGS after syscall");
        ptrace(PTRACE_SETREGS, pid, nullptr, &saved_regs);
        return false;
    }
    result = regs.rax;

    // Восстанавливаем исходные регистры
    ptrace(PTRACE_SETREGS, pid, nullptr, &saved_regs);

    return true;
}

// Remote mmap using the syscall helper
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

// Remote munmap
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

/**
 * Check if a library with the given path is already loaded in the process.
 * If found, write its base address into `existing_base` and return true.
 */
static bool is_library_already_loaded(pid_t pid, const std::string& lib_path, uintptr_t& existing_base) {
    std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream maps_file(maps_path);
    if (!maps_file.is_open()) return false;
    std::string line;
    while (std::getline(maps_file, line)) {
        if (line.find(lib_path) != std::string::npos) {
            size_t dash = line.find('-');
            if (dash != std::string::npos) {
                existing_base = std::stoul(line.substr(0, dash), nullptr, 16);
                return true;
            }
        }
    }
    return false;
}

/**
 * Stop all threads of the process and prepare the main thread for code injection.
 * Returns the list of stopped thread IDs (including main). On success, also returns
 * the main thread ID and saves its original registers.
 * If any step fails, all already stopped threads are resumed and an empty vector is returned.
 */
static std::vector<pid_t> stop_threads_and_prepare_main(pid_t pid, pid_t& main_tid,
                                                         struct user_regs_struct& saved_regs) {
    std::vector<pid_t> tids = get_all_threads(pid);
    if (tids.empty()) {
        std::cerr << "No threads found" << std::endl;
        return {};
    }

    if (!stop_all_threads(tids)) {
        resume_all_threads(tids);
        return {};
    }

    main_tid = pid;  // main thread ID is the process PID

    // Double PTRACE_SYSCALL to ensure the thread is out of kernel space
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

/**
 * Perform a test syscall (getpid) to verify that the remote syscall mechanism works.
 */
static bool test_syscall(pid_t tid, uintptr_t syscall_insn) {
    uintptr_t result;
    if (!remote_syscall(tid, result, 39, 0, 0, 0, 0, 0, 0, syscall_insn)) {
        std::cerr << "Test syscall (getpid) failed, remote_syscall is broken" << std::endl;
        return false;
    }
    std::cout << "Test getpid returned " << result << std::endl;
    return true;
}

/**
 * Inject shellcode that calls dlopen to load the new library.
 * This function assumes the main thread is stopped and its registers are saved in `saved_regs`.
 * On success, it returns the base address of the newly loaded library (found via /proc/pid/maps).
 * On failure, it restores the original registers, cleans up allocated memory, and returns 0.
 */
static uintptr_t inject_and_load_library(pid_t pid, pid_t tid,
                                         const std::string& new_lib_path,
                                         uintptr_t dlopen_addr,
                                         uintptr_t syscall_insn,
                                         struct user_regs_struct& saved_regs) {
    // Allocate remote memory
    size_t mem_size = 4096;
    uintptr_t remote_mem = remote_mmap(tid, mem_size,
                                       PROT_READ | PROT_WRITE | PROT_EXEC,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0,
                                       syscall_insn);
    if (remote_mem == 0) {
        std::cerr << "Failed to allocate remote memory" << std::endl;
        return 0;
    }

    uintptr_t shellcode_addr = remote_mem;
    uintptr_t path_addr      = remote_mem + 256;
    uintptr_t result_addr    = remote_mem + 512;

    // Write library path
    if (!write_remote_memory(pid, path_addr, new_lib_path.c_str(), new_lib_path.size() + 1)) {
        std::cerr << "Failed to write library path" << std::endl;
        remote_munmap(pid, remote_mem, mem_size, syscall_insn);
        return 0;
    }

    // Construct shellcode (identical to the one in the original function)
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
    *reinterpret_cast<uintptr_t*>(shellcode + DLOPEN_OFFSET) = dlopen_addr;
    *reinterpret_cast<uintptr_t*>(shellcode + RESULT_OFFSET) = result_addr;

    // Write shellcode byte by byte with verification
    for (size_t i = 0; i < sizeof(shellcode); i++) {
        uintptr_t addr = shellcode_addr + i;
        unsigned char val = shellcode[i];
        if (!write_remote_memory(pid, addr, &val, 1)) {
            std::cerr << "Failed to write byte at offset " << i << std::endl;
            remote_munmap(pid, remote_mem, mem_size, syscall_insn);
            return 0;
        }
        unsigned char verify = 0;
        if (read_remote_memory(pid, addr, &verify, 1)) {
            if (verify != val) {
                std::cerr << "Verification failed at offset " << i << std::endl;
                remote_munmap(pid, remote_mem, mem_size, syscall_insn);
                return 0;
            }
        } else {
            std::cerr << "Failed to verify at offset " << i << std::endl;
            remote_munmap(pid, remote_mem, mem_size, syscall_insn);
            return 0;
        }
    }
    std::cout << "Shellcode written and verified successfully" << std::endl;

    // Set RIP to shellcode
    struct user_regs_struct new_regs = saved_regs;
    new_regs.rip = shellcode_addr;
    if (ptrace(PTRACE_SETREGS, tid, nullptr, &new_regs) == -1) {
        perror("ptrace SETREGS");
        remote_munmap(pid, remote_mem, mem_size, syscall_insn);
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
        if (read_remote_memory(pid, result_addr, &handle, sizeof(handle)) && handle != 0) {
            std::cout << "dlopen succeeded, handle = 0x" << std::hex << handle << std::dec << std::endl;
            dlopen_ok = true;
        } else {
            std::cerr << "dlopen returned NULL" << std::endl;
        }
    } else {
        std::cerr << "Unexpected stop after shellcode: status=" << status << std::endl;
    }

    // Restore original registers
    ptrace(PTRACE_SETREGS, tid, nullptr, &saved_regs);

    if (!dlopen_ok) {
        remote_munmap(pid, remote_mem, mem_size, syscall_insn);
        return 0;
    }

    // Now find the base address of the newly loaded library by scanning /proc/pid/maps
    uintptr_t new_lib_base = 0;
    std::string maps_path = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream maps_file(maps_path);
    if (maps_file.is_open()) {
        std::string line;
        while (std::getline(maps_file, line)) {
            if (line.find(new_lib_path) != std::string::npos) {
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
        remote_munmap(pid, remote_mem, mem_size, syscall_insn);
        return 0;
    }
    std::cout << "New library base at 0x" << std::hex << new_lib_base << std::dec << std::endl;

    // Free the temporary memory (no longer needed)
    remote_munmap(pid, remote_mem, mem_size, syscall_insn);
    return new_lib_base;
}

/**
 * Apply a 5-byte jmp rel32 patch from old_func to new_func.
 * Returns true on success, false on failure.
 */
static bool apply_patch(pid_t pid, uintptr_t old_func, uintptr_t new_func) {
    int32_t rel32 = static_cast<int32_t>(new_func - (old_func + 5));
    unsigned char patch[5] = {0xE9, 0, 0, 0, 0};
    memcpy(patch + 1, &rel32, 4);

    if (!write_remote_memory(pid, old_func, patch, 5)) {
        std::cerr << "Failed to write patch at old function" << std::endl;
        return false;
    }

    // Verify the patch
    unsigned char verify[5];
    if (!read_remote_memory(pid, old_func, verify, 5)) {
        std::cerr << "Failed to read back patch for verification" << std::endl;
        return false;
    }
    if (memcmp(verify, patch, 5) != 0) {
        std::cerr << "Patch verification failed" << std::endl;
        return false;
    }

    std::cout << "Patch applied successfully" << std::endl;
    return true;
}

// -------------------------------------------------------------------
// Main replace_library function (now much shorter)
// -------------------------------------------------------------------
bool DL_Manager::replace_library(const std::string& target_lib_pattern, const std::string& new_lib_path) {
    // 1. Safety check and target library info
    if (!is_safe_to_replace(target_lib_pattern)) {
        std::cerr << "Not safe to replace library: threads are using it" << std::endl;
        return false;
    }
    LibraryInfo target_info = get_library_info(target_lib_pattern);
    if (target_info.base_addr == 0) {
        std::cerr << "Target library not found" << std::endl;
        return false;
    }
    if (new_lib_path == target_info.path) {
        std::cout << "New library is the same as target, nothing to do." << std::endl;
        return true;
    }

    // 2. Obtain libc and required addresses
    LibraryInfo libc_info = get_library_info("libc.so");
    if (libc_info.base_addr == 0) {
        std::cerr << "libc not found" << std::endl;
        return false;
    }
    uintptr_t dlopen_addr = get_symbol_address(libc_info.base_addr, "dlopen");
    if (dlopen_addr == 0) {
        std::cerr << "Failed to find dlopen in libc" << std::endl;
        return false;
    }
    uintptr_t syscall_insn = find_syscall_instruction(pid_, this, libc_info.base_addr);
    if (syscall_insn == 0) {
        std::cerr << "Failed to find syscall instruction in libc" << std::endl;
        return false;
    }

    // 3. Stop all threads and prepare main thread
    struct user_regs_struct saved_regs;
    pid_t main_tid;
    std::vector<pid_t> tids = stop_threads_and_prepare_main(pid_, main_tid, saved_regs);
    if (tids.empty()) return false;

    // 4. Test syscall mechanism
    if (!test_syscall(main_tid, syscall_insn)) {
        resume_all_threads(tids);
        return false;
    }

    // 5. Determine base address of new library (either already loaded or load it now)
    uintptr_t new_lib_base = 0;
    if (is_library_already_loaded(pid_, new_lib_path, new_lib_base)) {
        std::cout << "Library already loaded, using existing copy." << std::endl;
    } else {
        new_lib_base = inject_and_load_library(pid_, main_tid, new_lib_path,
                                               dlopen_addr, syscall_insn, saved_regs);
        if (new_lib_base == 0) {
            resume_all_threads(tids);
            return false;
        }
    }

    // 6. Get addresses of the target function in both libraries
    uintptr_t old_func = get_symbol_address(target_info.base_addr, "perform_op");
    uintptr_t new_func = get_symbol_address(new_lib_base, "perform_op");
    if (old_func == 0 || new_func == 0) {
        std::cerr << "Failed to find perform_op in one of the libraries" << std::endl;
        resume_all_threads(tids);
        return false;
    }
    std::cout << "Old function at 0x" << std::hex << old_func << std::dec << std::endl;
    std::cout << "New function at 0x" << std::hex << new_func << std::dec << std::endl;

    // 7. Apply patch if the addresses differ
    bool patch_success = true;
    if (old_func == new_func) {
        std::cout << "Old and new function addresses are identical, no patch needed." << std::endl;
    } else {
        patch_success = apply_patch(pid_, old_func, new_func);
    }

    // 8. Resume all threads and return result
    resume_all_threads(tids);
    return patch_success;
}
