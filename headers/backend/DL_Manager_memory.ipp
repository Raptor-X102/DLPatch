//=============================================================================
// DL_Manager_memory.ipp
// Remote memory operations using ptrace and process_vm_readv
//=============================================================================

/**
 * @brief Write data to remote process memory using ptrace POKEDATA
 * @param pid Target process ID
 * @param addr Address to write to
 * @param data Data to write
 * @param size Number of bytes to write
 * @return true if write succeeded
 * 
 * Handles unaligned writes by reading-modifying-writing whole words.
 * Word size is sizeof(long) (8 bytes on x86_64).
 */
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

/**
 * @brief Read data from remote process memory using process_vm_readv
 * @param pid Target process ID
 * @param addr Address to read from
 * @param buffer Local buffer to store data
 * @param size Number of bytes to read
 * @return true if read succeeded
 * 
 * More efficient than ptrace PEEKDATA for larger reads.
 */
static bool read_remote_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size) {
    struct iovec local = {buffer, size};
    struct iovec remote = {reinterpret_cast<void*>(addr), size};
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    return n == static_cast<ssize_t>(size);
}

/**
 * @brief Execute mmap syscall in remote process
 * @param pid Target process ID
 * @param length Size of mapping
 * @param prot Protection flags
 * @param flags Mapping flags
 * @param fd File descriptor (-1 for anonymous)
 * @param offset File offset
 * @param syscall_insn_addr Address of syscall instruction in remote process
 * @return Address of mapped memory, or 0 on failure
 */
static uintptr_t remote_mmap(pid_t pid, size_t length, int prot, int flags, int fd, off_t offset,
                             uintptr_t syscall_insn_addr) {
    uintptr_t result;
    if (!Arch::remote_syscall(pid, result, Arch::SYS_MMAP, 
        0, length, prot, flags, fd, offset, syscall_insn_addr)) {
        return 0;
    }
    return result;
}

/**
 * @brief Execute munmap syscall in remote process
 * @param pid Target process ID
 * @param addr Address to unmap
 * @param length Size to unmap
 * @param syscall_insn_addr Address of syscall instruction in remote process
 * @return true if munmap succeeded
 */
static bool remote_munmap(pid_t pid, uintptr_t addr, size_t length, uintptr_t syscall_insn_addr) {
    uintptr_t result;
    if (!Arch::remote_syscall(pid, result, Arch::SYS_MUNMAP,
        addr, length, 0, 0, 0, 0, syscall_insn_addr)) {
        return false;
    }
    return result == 0;
}

/**
 * @brief Read remote memory (public wrapper)
 * @param addr Address to read from
 * @param buffer Local buffer
 * @param size Number of bytes
 * @return true if read succeeded
 */
bool DL_Manager::read_remote_memory_raw(uintptr_t addr, void* buffer, size_t size) const {
    return read_remote_memory(pid_, addr, buffer, size);
}

/**
 * @brief Write dlopen shellcode to remote memory
 * @param tid Thread ID
 * @param shellcode_addr Address where shellcode will be placed
 * @param path_addr Address where library path is stored
 * @param result_addr Address where dlopen result will be stored
 * @return true if shellcode written successfully
 */
bool DL_Manager::write_shellcode(pid_t tid, uintptr_t shellcode_addr,
                                                   uintptr_t path_addr, uintptr_t result_addr) {
    auto shellcode = Arch::generate_dlopen_shellcode(path_addr, dlopen_addr_, result_addr);
    
    LOG_DBG("Shellcode size: %zu bytes", shellcode.size());
    LOG_DBG("Shellcode before writing:");
    for (size_t i = 0; i < shellcode.size(); i += 8) {
        size_t chunk = std::min(shellcode.size() - i, size_t(8));
        uint64_t val = 0;
        memcpy(&val, &shellcode[i], chunk);
        LOG_DBG("  offset %3zu: 0x%016lx", i, val);
    }
    
#ifdef DEBUG
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
#else
    (void)result_addr;
#endif
    
    if (!write_remote_memory(tid, shellcode_addr, shellcode.data(), shellcode.size()))
        return false;
    
#ifdef DEBUG
    std::vector<uint8_t> verify(shellcode.size());
    if (!read_remote_memory(tid, shellcode_addr, verify.data(), verify.size()))
        return false;
    if (memcmp(verify.data(), shellcode.data(), shellcode.size()) != 0)
        return false;
    LOG_DBG("Shellcode written and verified successfully");
#else
    LOG_DBG("Shellcode written successfully");
#endif
    
    return true;
}

/**
 * @brief Allocate memory in remote process using mmap
 * @param tid Thread ID
 * @param size Size to allocate
 * @return Address of allocated memory, or 0 on failure
 */
uintptr_t DL_Manager::allocate_remote_memory(pid_t tid, size_t size) {
    return remote_mmap(tid, size,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0,
                       syscall_insn_);
}
