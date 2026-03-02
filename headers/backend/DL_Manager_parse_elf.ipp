//=============================================================================
// DL_Manager_parse_elf.ipp
// ELF parsing utilities for reading dynamic section, symbols, and GOT
//=============================================================================

/**
 * @brief Read and validate ELF header from remote process
 * @param pid Target process ID
 * @param lib_base Base address of library
 * @param ehdr [out] ELF header structure
 * @return true if header read successfully and is valid ELF
 */
static bool read_elf_header(pid_t pid, uintptr_t lib_base, Elf64_Ehdr& ehdr) {
    if (!read_struct(pid, lib_base, ehdr)) {
        LOG_ERR("Failed to read ELF header at 0x%lx", lib_base);
        return false;
    }
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        LOG_ERR("Not a valid ELF file at 0x%lx", lib_base);
        return false;
    }
    return true;
}

/**
 * @brief Parse GNU hash table to determine number of symbols
 * @param pid Target process ID
 * @param gnu_hash_addr Address of GNU hash table
 * @return Number of symbols (nchain) or 0 on failure
 */
static uint32_t parse_gnu_hash(pid_t pid, uintptr_t gnu_hash_addr) {
    uint32_t header[4];
    if (!read_process_memory(pid, gnu_hash_addr, header, sizeof(header))) {
        LOG_DBG("Failed to read GNU hash header");
        return 0;
    }
    uint32_t nbucket = header[0];
    uint32_t symoffset = header[1];
    uint32_t bloom_size = header[2];
    
    uintptr_t bucket_addr = gnu_hash_addr + 16 + bloom_size * 8;
    uintptr_t chain_addr = bucket_addr + nbucket * 4;

    uint32_t max_idx = symoffset - 1;
    for (uint32_t i = 0; i < nbucket; ++i) {
        uint32_t bucket_val;
        if (!read_process_memory(pid, bucket_addr + i * 4, &bucket_val, 4)) {
            LOG_DBG("Failed to read bucket[%u]", i);
            continue;
        }
        if (bucket_val == 0) continue;

        uint32_t j = bucket_val;
        while (true) {
            uint32_t chain_val;
            if (!read_process_memory(pid, chain_addr + (j - symoffset) * 4, &chain_val, 4)) {
                LOG_DBG("Failed to read chain for index %u", j);
                break;
            }
            if (j > max_idx) max_idx = j;
            if (chain_val & 1) break;
            ++j;
        }
    }
    return max_idx + 1;
}

/**
 * @brief Parse dynamic section information from ELF
 * @param pid Target process ID
 * @param lib_base Base address of library
 * @param info [out] Filled DynamicInfo structure
 * @return true if successful
 * 
 * Reads ELF header, program headers, and dynamic section to extract
 * addresses of string table, symbol table, relocation tables, etc.
 */
static bool parse_dynamic_info(pid_t pid, uintptr_t lib_base, DynamicInfo& info) {
    Elf64_Ehdr ehdr;
    if (!read_elf_header(pid, lib_base, ehdr)) {
        return false;
    }

    std::vector<Elf64_Phdr> phdrs(ehdr.e_phnum);
    uintptr_t phdr_addr = lib_base + ehdr.e_phoff;
    if (!read_process_memory(pid, phdr_addr, phdrs.data(), ehdr.e_phnum * sizeof(Elf64_Phdr))) {
        LOG_ERR("Failed to read program headers at 0x%lx", phdr_addr);
        return false;
    }

    uintptr_t dyn_vaddr = 0;
    size_t dyn_filesz = 0;
    for (const auto& phdr : phdrs) {
        if (phdr.p_type == PT_DYNAMIC) {
            dyn_vaddr = lib_base + phdr.p_vaddr;
            dyn_filesz = phdr.p_filesz;
            break;
        }
    }
    if (dyn_vaddr == 0) {
        LOG_ERR("No PT_DYNAMIC segment found");
        return false;
    }

    size_t dyn_entries = dyn_filesz / sizeof(Elf64_Dyn);
    if (dyn_entries == 0) {
        LOG_ERR("Dynamic section size is zero");
        return false;
    }

    std::vector<Elf64_Dyn> dyn(dyn_entries);
    if (!read_process_memory(pid, dyn_vaddr, dyn.data(), dyn_filesz)) {
        LOG_ERR("Failed to read dynamic section at 0x%lx", dyn_vaddr);
        return false;
    }

    for (const auto& d : dyn) {
        switch (d.d_tag) {
            case DT_STRTAB: info.strtab = d.d_un.d_ptr; break;
            case DT_SYMTAB: info.symtab = d.d_un.d_ptr; break;
            case DT_STRSZ:  info.strsz = d.d_un.d_val; break;
            case DT_SYMENT: info.syment = d.d_un.d_val; break;
            case DT_JMPREL: info.jmprel = d.d_un.d_ptr; break;
            case DT_PLTRELSZ: info.pltrelsz = d.d_un.d_val; break;
            case DT_PLTREL: info.pltrel_type = d.d_un.d_val; break;
            case DT_HASH:   info.hash = d.d_un.d_ptr; break;
            case DT_GNU_HASH: info.gnu_hash = d.d_un.d_ptr; break;
            default: break;
        }
    }

    if (info.strtab == 0 || info.symtab == 0 || info.strsz == 0 || info.syment == 0) {
        LOG_ERR("Missing required dynamic entries (STRTAB, SYMTAB, STRSZ, SYMENT)");
        return false;
    }
    return true;
}

//=============================================================================
// Symbol iteration utilities
//=============================================================================

using SymbolCallback = std::function<bool(const Elf64_Sym& sym, const std::string& name)>;

/**
 * @brief Iterate through all dynamic symbols using pre-parsed DynamicInfo
 * @param pid Target process ID
 * @param info DynamicInfo structure
 * @param callback Called for each symbol (return false to stop)
 * @return true if iteration completed
 */
static bool iterate_dynamic_symbols(pid_t pid, const DynamicInfo& info, const SymbolCallback& callback) {
    uint32_t nchain = 0;

    if (info.hash != 0) {
        uint32_t nbucket;
        if (!read_struct(pid, info.hash, nbucket) || !read_struct(pid, info.hash + 4, nchain))
            return false;
    } else if (info.gnu_hash != 0) {
        nchain = parse_gnu_hash(pid, info.gnu_hash);
        if (nchain == 0) nchain = 10000;
    } else {
        nchain = 10000;
    }

    for (uint32_t i = 0; i < nchain; ++i) {
        Elf64_Sym sym;
        uintptr_t sym_addr = info.symtab + i * info.syment;
        if (!read_struct(pid, sym_addr, sym)) {
            if (i > 0) break;
            continue;
        }

        if (sym.st_name == 0) continue;

        uintptr_t name_addr = info.strtab + sym.st_name;
        std::string name = read_string(pid, name_addr, info.strsz);
        if (name.empty()) continue;

        if (!callback(sym, name)) {
            break;
        }
    }

    return true;
}

/**
 * @brief Iterate through all dynamic symbols of a library
 * @param pid Target process ID
 * @param lib_base Base address of library
 * @param callback Called for each symbol (return false to stop)
 * @return true if iteration completed
 */
static bool iterate_dynamic_symbols(pid_t pid, uintptr_t lib_base, const SymbolCallback& callback) {
    DynamicInfo info;
    if (!parse_dynamic_info(pid, lib_base, info)) {
        LOG_DBG("iterate_dynamic_symbols: failed to parse dynamic info at 0x%lx", lib_base);
        return false;
    }
    return iterate_dynamic_symbols(pid, info, callback);
}
