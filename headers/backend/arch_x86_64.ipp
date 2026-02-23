#ifndef ARCH_X86_64_IPP
#define ARCH_X86_64_IPP

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>
#include <cstdint>
#include <vector>
#include <cstring>

// Forward declaration (достаточно для объявления)
class DL_Manager;

namespace Arch {

// Register access (можно оставить inline реализации)
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

// Константы
constexpr long SYS_MMAP = 9;
constexpr long SYS_MUNMAP = 11;
constexpr long SYS_GETPID = 39;
constexpr int R_JUMP_SLOT = 7;

// Вспомогательные генераторы кода (могут быть inline)
inline std::vector<uint8_t> breakpoint_instruction() { return {0xCC}; }

inline std::vector<uint8_t> generate_dlopen_shellcode(uintptr_t path_addr, uintptr_t dlopen_addr, uintptr_t result_addr) {
    std::vector<uint8_t> shellcode = {
        0x55, 0x48, 0x89, 0xe5, 0x57, 0x56, 0x50, 0x48, 0x83, 0xec, 0x08,
        0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xc7, 0xc6, 0x02, 0x00, 0x00, 0x00,
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xd0,
        0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x07,
        0x48, 0x83, 0xc4, 0x08, 0x58, 0x5e, 0x5f, 0x5d, 0xcc, 0xc3
    };
    const size_t PATH_OFFSET = 13, DLOPEN_OFFSET = 30, RESULT_OFFSET = 42;
    *reinterpret_cast<uintptr_t*>(&shellcode[PATH_OFFSET]) = path_addr;
    *reinterpret_cast<uintptr_t*>(&shellcode[DLOPEN_OFFSET]) = dlopen_addr;
    *reinterpret_cast<uintptr_t*>(&shellcode[RESULT_OFFSET]) = result_addr;
    return shellcode;
}

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

inline std::vector<uint8_t> create_jmp_patch(uintptr_t from_addr, uintptr_t to_addr) {
    int32_t rel32 = static_cast<int32_t>(to_addr - (from_addr + 5));
    std::vector<uint8_t> patch(5);
    patch[0] = 0xE9;
    memcpy(&patch[1], &rel32, 4);
    return patch;
}

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

bool remote_syscall(pid_t pid, uintptr_t& result, long number,
                    uintptr_t arg1, uintptr_t arg2, uintptr_t arg3,
                    uintptr_t arg4, uintptr_t arg5, uintptr_t arg6,
                    uintptr_t syscall_insn_addr) {
    user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) return false;
    user_regs_struct saved = regs;
    
    set_syscall_num(regs, number);
    set_arg0(regs, arg1);
    set_arg1(regs, arg2);
    set_arg2(regs, arg3);
    set_arg3(regs, arg4);
    set_arg4(regs, arg5);
    set_arg5(regs, arg6);
    set_ip(regs, syscall_insn_addr);
    
    if (ptrace(PTRACE_SETREGS, pid, nullptr, &regs) == -1) return false;
    if (ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr) == -1) return false;
    
    int status;
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) return false;
    
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) return false;
    result = get_syscall_ret(regs);
    ptrace(PTRACE_SETREGS, pid, nullptr, &saved);
    return true;
}

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
