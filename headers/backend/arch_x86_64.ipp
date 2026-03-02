//=============================================================================
// arch_x86_64.ipp
// x86-64 architecture-specific implementations
//=============================================================================

#ifndef ARCH_X86_64_IPP
#define ARCH_X86_64_IPP

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>
#include <cstdint>
#include <vector>
#include <cstring>

// Forward declaration for find_syscall_instruction
class DL_Manager;

namespace Arch {

//=============================================================================
// Register accessors - inline for performance
//=============================================================================

inline uintptr_t get_ip(const user_regs_struct& regs) { return regs.rip; }
inline void set_ip(user_regs_struct& regs, uintptr_t val) { regs.rip = val; }
inline uintptr_t get_sp(const user_regs_struct& regs) { return regs.rsp; }
inline void set_sp(user_regs_struct& regs, uintptr_t val) { regs.rsp = val; }

inline uintptr_t get_arg0(const user_regs_struct& regs) { return regs.rdi; }
inline void set_arg0(user_regs_struct& regs, uintptr_t val) { regs.rdi = val; }
inline uintptr_t get_arg1(const user_regs_struct& regs) { return regs.rsi; }
inline void set_arg1(user_regs_struct& regs, uintptr_t val) { regs.rsi = val; }
inline uintptr_t get_arg2(const user_regs_struct& regs) { return regs.rdx; }
inline void set_arg2(user_regs_struct& regs, uintptr_t val) { regs.rdx = val; }
inline uintptr_t get_arg3(const user_regs_struct& regs) { return regs.r10; }
inline void set_arg3(user_regs_struct& regs, uintptr_t val) { regs.r10 = val; }
inline uintptr_t get_arg4(const user_regs_struct& regs) { return regs.r8; }
inline void set_arg4(user_regs_struct& regs, uintptr_t val) { regs.r8 = val; }
inline uintptr_t get_arg5(const user_regs_struct& regs) { return regs.r9; }
inline void set_arg5(user_regs_struct& regs, uintptr_t val) { regs.r9 = val; }

inline uintptr_t get_syscall_num(const user_regs_struct& regs) { return regs.rax; }
inline void set_syscall_num(user_regs_struct& regs, uintptr_t val) { regs.rax = val; }
inline uintptr_t get_syscall_ret(const user_regs_struct& regs) { return regs.rax; }
inline void set_syscall_ret(user_regs_struct& regs, uintptr_t val) { regs.rax = val; }

//=============================================================================
// System call numbers for x86-64 Linux
//=============================================================================

constexpr long SYS_MMAP = 9;
constexpr long SYS_MUNMAP = 11;
constexpr long SYS_GETPID = 39;
constexpr long SYS_MPROTECT = 10;
constexpr int R_JUMP_SLOT = 7;  // R_X86_64_JUMP_SLOT relocation type

//=============================================================================
// Debug helpers
//=============================================================================

inline std::vector<uint8_t> breakpoint_instruction() { return {0xCC}; }

//=============================================================================
// Shellcode generation
//=============================================================================

/**
 * @brief Generate shellcode to call dlopen in remote process
 * @param path_addr Address where library path is stored
 * @param dlopen_addr Address of dlopen function
 * @param result_addr Address where result (handle) should be stored
 * @return Vector of bytes containing shellcode
 * 
 * The shellcode:
 * 1. Sets up stack frame and saves registers
 * 2. Moves path_addr to RDI (first argument)
 * 3. Moves RTLD_NOW (2) to RSI (second argument)
 * 4. Calls dlopen
 * 5. Stores returned handle at result_addr
 * 6. Restores registers and traps (int3) for debugger
 */
inline std::vector<uint8_t> generate_dlopen_shellcode(uintptr_t path_addr, uintptr_t dlopen_addr, uintptr_t result_addr) {
    std::vector<uint8_t> shellcode = {
        // Prologue: save registers and set up stack frame
        0x55,                               // push rbp
        0x48, 0x89, 0xe5,                   // mov rbp, rsp
        0x57,                               // push rdi
        0x56,                               // push rsi
        0x50,                               // push rax
        0x48, 0x83, 0xec, 0x08,             // sub rsp, 8
        
        // First argument for dlopen: path_addr -> rdi
        0x48, 0xbf,                         // mov rdi, imm64
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // placeholder for path_addr
        
        // Second argument for dlopen: flags (RTLD_NOW = 2) -> rsi
        0x48, 0xc7, 0xc6, 0x02, 0x00, 0x00, 0x00, // mov rsi, 2
        
        // Load dlopen address into rax
        0x48, 0xb8,                         // mov rax, imm64
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // placeholder for dlopen_addr
        
        // Call dlopen
        0xff, 0xd0,                         // call rax
        
        // Save result (handle) to result_addr
        0x48, 0xbf,                         // mov rdi, imm64
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // placeholder for result_addr
        0x48, 0x89, 0x07,                   // mov [rdi], rax
        
        // Epilogue: restore stack and registers
        0x48, 0x83, 0xc4, 0x08,             // add rsp, 8
        0x58,                               // pop rax
        0x5e,                               // pop rsi
        0x5f,                               // pop rdi
        0x5d,                               // pop rbp
        
        // Trap to debugger and return
        0xcc,                               // int3
        0xc3                                // ret
    };
    
    // Patch placeholders with actual addresses
    const size_t PATH_OFFSET = 13;          // offset of path_addr placeholder
    const size_t DLOPEN_OFFSET = 30;        // offset of dlopen_addr placeholder
    const size_t RESULT_OFFSET = 42;        // offset of result_addr placeholder
    
    *reinterpret_cast<uintptr_t*>(&shellcode[PATH_OFFSET]) = path_addr;
    *reinterpret_cast<uintptr_t*>(&shellcode[DLOPEN_OFFSET]) = dlopen_addr;
    *reinterpret_cast<uintptr_t*>(&shellcode[RESULT_OFFSET]) = result_addr;
    
    return shellcode;
}

/**
 * @brief Generate shellcode to call dlclose in remote process
 * @param handle Handle returned by dlopen
 * @param dlclose_addr Address of dlclose function
 * @param result_addr Address where result (0 on success) should be stored
 * @return Vector of bytes containing shellcode
 * 
 * Similar to dlopen shellcode but calls dlclose with the handle as argument.
 */
inline std::vector<uint8_t> generate_dlclose_shellcode(uintptr_t handle, uintptr_t dlclose_addr, uintptr_t result_addr) {
    std::vector<uint8_t> shellcode = {
        // prologue: save registers
        0x55,                               // push rbp
        0x48, 0x89, 0xe5,                   // mov rbp, rsp
        0x53,                               // push rbx
        
        // align stack (after 2 pushes = 16 bytes, need 8 more for call alignment)
        0x48, 0x83, 0xec, 0x08,             // sub rsp, 8
        
        // save result_addr in rbx (callee-saved)
        0x48, 0xbb,                         // mov rbx, imm64
        (uint8_t)((result_addr >> 0) & 0xff),
        (uint8_t)((result_addr >> 8) & 0xff),
        (uint8_t)((result_addr >> 16) & 0xff),
        (uint8_t)((result_addr >> 24) & 0xff),
        (uint8_t)((result_addr >> 32) & 0xff),
        (uint8_t)((result_addr >> 40) & 0xff),
        (uint8_t)((result_addr >> 48) & 0xff),
        (uint8_t)((result_addr >> 56) & 0xff),
        
        // first argument: handle -> rdi
        0x48, 0xbf,                         // mov rdi, imm64
        (uint8_t)((handle >> 0) & 0xff),
        (uint8_t)((handle >> 8) & 0xff),
        (uint8_t)((handle >> 16) & 0xff),
        (uint8_t)((handle >> 24) & 0xff),
        (uint8_t)((handle >> 32) & 0xff),
        (uint8_t)((handle >> 40) & 0xff),
        (uint8_t)((handle >> 48) & 0xff),
        (uint8_t)((handle >> 56) & 0xff),
        
        // dlclose address -> rax
        0x48, 0xb8,                         // mov rax, imm64
        (uint8_t)((dlclose_addr >> 0) & 0xff),
        (uint8_t)((dlclose_addr >> 8) & 0xff),
        (uint8_t)((dlclose_addr >> 16) & 0xff),
        (uint8_t)((dlclose_addr >> 24) & 0xff),
        (uint8_t)((dlclose_addr >> 32) & 0xff),
        (uint8_t)((dlclose_addr >> 40) & 0xff),
        (uint8_t)((dlclose_addr >> 48) & 0xff),
        (uint8_t)((dlclose_addr >> 56) & 0xff),
        
        // call dlclose
        0xff, 0xd0,                         // call rax
        
        // save result (rax) to [rbx]
        0x48, 0x89, 0x03,                   // mov [rbx], rax
        
        // restore stack alignment
        0x48, 0x83, 0xc4, 0x08,             // add rsp, 8
        
        // restore registers
        0x5b,                               // pop rbx
        0x5d,                               // pop rbp
        
        // trap for debugger
        0xcc                                // int3
    };
    
    return shellcode;
}

/**
 * @brief Create a 5-byte relative JMP instruction
 * @param from_addr Address where JMP will be placed
 * @param to_addr Target address to jump to
 * @return Vector of 5 bytes: 0xE9 + 32-bit relative offset
 * 
 * Calculates relative offset: to_addr - (from_addr + 5)
 */
inline std::vector<uint8_t> create_jmp_patch(uintptr_t from_addr, uintptr_t to_addr) {
    int32_t rel32 = static_cast<int32_t>(to_addr - (from_addr + 5));
    std::vector<uint8_t> patch(5);
    patch[0] = 0xE9;
    memcpy(&patch[1], &rel32, 4);
    return patch;
}

//=============================================================================
// Syscall instruction location
//=============================================================================

/**
 * @brief Find the address of a syscall instruction in libc
 * @param mgr DL_Manager instance (for memory reading)
 * @param libc_base Base address of libc
 * @return Address of syscall instruction, or 0 if not found
 * 
 * Looks for the pattern 0x0F 0x05 (syscall) in the syscall() function.
 */
uintptr_t find_syscall_instruction(DL_Manager* mgr, uintptr_t libc_base) {
    uintptr_t syscall_func = mgr->get_symbol_address(libc_base, "syscall");
    if (!syscall_func) return 0;
    
    unsigned char buffer[64];
    if (!mgr->read_remote_memory_raw(syscall_func, buffer, sizeof(buffer)))
        return 0;
    
    for (int i = 0; i < (int)sizeof(buffer) - 1; ++i) {
        if (buffer[i] == 0x0f && buffer[i+1] == 0x05) {
            return syscall_func + i;
        }
    }
    return 0;
}

//=============================================================================
// Remote syscall execution
//=============================================================================

/**
 * @brief Execute a system call in a remote thread
 * @param pid Thread ID
 * @param result [out] Return value of syscall
 * @param number Syscall number
 * @param arg1-6 Syscall arguments
 * @param syscall_insn_addr Address of syscall instruction in remote process
 * @return true if syscall executed successfully
 * 
 * This function:
 * 1. Saves current registers of the thread
 * 2. Sets up registers for the desired syscall
 * 3. Single-steps through the syscall instruction
 * 4. Reads the result from RAX
 * 5. Restores original registers
 */
bool remote_syscall(pid_t pid, uintptr_t& result, long number,
                    uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
                    uintptr_t arg4, uintptr_t arg5, uintptr_t arg6,
                    uintptr_t syscall_insn_addr) {
    
    LOG_DBG("remote_syscall: pid=%d, syscall=%ld, syscall_insn_addr=0x%lx", 
            pid, number, syscall_insn_addr);
    LOG_DBG("  args: 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx",
            arg1, arg2, arg3, arg4, arg5, arg6);
    
    // Save current registers
    user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
        LOG_ERR("  PTRACE_GETREGS failed: %s", strerror(errno));
        return false;
    }
    LOG_DBG("  Saved regs: IP=0x%llx, SP=0x%llx, RAX=0x%llx",
            (unsigned long long)get_ip(regs),
            (unsigned long long)get_sp(regs),
            (unsigned long long)get_syscall_ret(regs));
    
    user_regs_struct saved = regs;
    
    // Set up registers for syscall
    set_syscall_num(regs, number);
    set_arg0(regs, arg1);
    set_arg1(regs, arg2);
    set_arg2(regs, arg3);
    set_arg3(regs, arg4);
    set_arg4(regs, arg5);
    set_arg5(regs, arg6);
    set_ip(regs, syscall_insn_addr);
    
    LOG_DBG("  Set regs for syscall: IP=0x%llx, SYSCALL=%ld",
            (unsigned long long)get_ip(regs), get_syscall_num(regs));
    
    if (ptrace(PTRACE_SETREGS, pid, nullptr, &regs) == -1) {
        LOG_ERR("  PTRACE_SETREGS failed: %s", strerror(errno));
        return false;
    }
    
    LOG_DBG("  Doing PTRACE_SINGLESTEP...");
    if (ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr) == -1) {
        LOG_ERR("  PTRACE_SINGLESTEP failed: %s", strerror(errno));
        return false;
    }
    
    int status;
    waitpid(pid, &status, 0);
    LOG_DBG("  waitpid returned status=0x%x", status);
    
    if (!WIFSTOPPED(status)) {
        LOG_ERR("  Thread did not stop after singlestep");
        return false;
    }
    
    int sig = WSTOPSIG(status);
    LOG_DBG("  Thread stopped with signal %d", sig);
    
    if (sig != SIGTRAP) {
        LOG_ERR("  Expected SIGTRAP, got %d", sig);
        return false;
    }
    
    // Get result
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
        LOG_ERR("  PTRACE_GETREGS after syscall failed: %s", strerror(errno));
        return false;
    }
    
    result = get_syscall_ret(regs);
    LOG_DBG("  Syscall returned 0x%lx (%ld)", result, result);
    
    // Restore original registers
    if (ptrace(PTRACE_SETREGS, pid, nullptr, &saved) == -1) {
        LOG_ERR("  Failed to restore registers: %s", strerror(errno));
        // Don't return false here - we already have the result
    }
    
    LOG_DBG("  remote_syscall successful");
    return true;
}

//=============================================================================
// Debugging utilities
//=============================================================================

/**
 * @brief Dump registers and code around RIP for debugging
 * @param tid Thread ID
 * @param mgr DL_Manager instance (for memory reading)
 * 
 * Called when shellcode crashes to help diagnose the issue.
 */
inline void dump_registers(pid_t tid, DL_Manager* mgr) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) == -1) {
        LOG_ERR("Failed to get registers for dump");
        return;
    }
    
    LOG_ERR("Fault registers:");
    LOG_ERR("  RIP = 0x%llx", (unsigned long long)get_ip(regs));
    LOG_ERR("  RSP = 0x%llx", (unsigned long long)get_sp(regs));
    LOG_ERR("  RAX = 0x%llx", (unsigned long long)regs.rax);
    LOG_ERR("  RBX = 0x%llx", (unsigned long long)regs.rbx);
    LOG_ERR("  RCX = 0x%llx", (unsigned long long)regs.rcx);
    LOG_ERR("  RDX = 0x%llx", (unsigned long long)regs.rdx);
    LOG_ERR("  RDI = 0x%llx", (unsigned long long)regs.rdi);
    LOG_ERR("  RSI = 0x%llx", (unsigned long long)regs.rsi);
    LOG_ERR("  RBP = 0x%llx", (unsigned long long)regs.rbp);
    LOG_ERR("  R8  = 0x%llx", (unsigned long long)regs.r8);
    LOG_ERR("  R9  = 0x%llx", (unsigned long long)regs.r9);
    LOG_ERR("  R10 = 0x%llx", (unsigned long long)regs.r10);
    LOG_ERR("  R11 = 0x%llx", (unsigned long long)regs.r11);
    LOG_ERR("  R12 = 0x%llx", (unsigned long long)regs.r12);
    LOG_ERR("  R13 = 0x%llx", (unsigned long long)regs.r13);
    LOG_ERR("  R14 = 0x%llx", (unsigned long long)regs.r14);
    LOG_ERR("  R15 = 0x%llx", (unsigned long long)regs.r15);
    
    // Dump code around RIP
    unsigned char code[32];
    uintptr_t dump_addr = get_ip(regs) & ~0xf;
    if (mgr->read_remote_memory_raw(dump_addr, code, sizeof(code))) {
        LOG_ERR("Code at 0x%lx:", dump_addr);
        for (int i = 0; i < 32; i += 8) {
            uint64_t val;
            memcpy(&val, code + i, 8);
            LOG_ERR("  0x%lx: 0x%016lx", dump_addr + i, val);
        }
    }
}

} // namespace Arch

#endif
