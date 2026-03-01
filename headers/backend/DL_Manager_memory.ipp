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

bool DL_Manager::read_remote_memory_raw(uintptr_t addr, void* buffer, size_t size) const {
    return read_remote_memory(pid_, addr, buffer, size);
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

uintptr_t DL_Manager::allocate_remote_memory(pid_t tid, size_t size) {
    return remote_mmap(tid, size,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0,
                       syscall_insn_);
}
