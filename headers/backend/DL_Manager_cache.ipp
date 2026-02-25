#include <algorithm>

inline void DL_Manager::ensure_cache(uintptr_t lib_base) const {
    auto it = library_cache_.find(lib_base);
    if (it != library_cache_.end() && it->second.parsed)
        return;

    CachedLibraryData data;
    DynamicInfo info;
    if (!parse_dynamic_info(pid_, lib_base, info)) {
        LOG_WARN("Failed to parse dynamic info for caching at 0x%lx", lib_base);
        library_cache_[lib_base] = data;
        return;
    }

    data.symbols = parse_symbols_from_dynamic(lib_base, info);
    data.got_entries = parse_got_entries(lib_base, info);
    data.parsed = true;
    library_cache_[lib_base] = data;
    LOG_DBG("Cached library at 0x%lx: %zu symbols, %zu GOT entries",
            lib_base, data.symbols.size(), data.got_entries.size());
}

inline void DL_Manager::invalidate_cache(uintptr_t lib_base) {
    if (lib_base == 0) {
        library_cache_.clear();
        LOG_DBG("Cleared entire cache");
    } else {
        library_cache_.erase(lib_base);
        LOG_DBG("Invalidated cache for 0x%lx", lib_base);
    }
}

inline std::vector<SymbolInfo> DL_Manager::parse_symbols_from_dynamic(uintptr_t lib_base,
                                                                       const DynamicInfo& info) const {
    std::vector<SymbolInfo> symbols;
    uint32_t nchain = 0;

    // Determine number of symbols from hash table
    if (info.hash != 0) {
        uint32_t nbucket;
        if (!read_struct(pid_, info.hash, nbucket) || !read_struct(pid_, info.hash + 4, nchain))
            return symbols;
    } else if (info.gnu_hash != 0) {
        nchain = parse_gnu_hash(pid_, info.gnu_hash);
        if (nchain == 0) nchain = 10000; // Fallback
    } else {
        nchain = 10000; // Fallback
    }

    // Iterate through symbol table
    for (uint32_t i = 0; i < nchain; ++i) {
        Elf64_Sym sym;
        uintptr_t sym_addr = info.symtab + i * info.syment;
        if (!read_struct(pid_, sym_addr, sym)) {
            if (i > 0) break;
            continue;
        }
        
        int type = ELF64_ST_TYPE(sym.st_info);
        int bind = ELF64_ST_BIND(sym.st_info);
        int vis = ELF64_ST_VISIBILITY(sym.st_other);
        
        // Quick filter for functions we might want to patch
        bool is_patchable = true;
        
        // Must be a function
        if (type != STT_FUNC) {
            is_patchable = false;
        }
        // Must have a name and valid address
        else if (sym.st_name == 0 || sym.st_value == 0) {
            is_patchable = false;
        }
        // Must be global or weak (exported)
        else if (bind != STB_GLOBAL && bind != STB_WEAK) {
            is_patchable = false;
        }
        // Must have default visibility (not hidden)
        else if (vis != STV_DEFAULT) {
            is_patchable = false;
        }
        // Must have non-zero size (not a PLT stub)
        else if (sym.st_size == 0) {
            is_patchable = false;
        }
        
        if (!is_patchable) {
            continue;
        }
        
        // Read symbol name
        uintptr_t name_addr = info.strtab + sym.st_name;
        std::string name = read_string(pid_, name_addr, info.strsz);
        
        // Additional sanity check - name shouldn't be empty
        if (name.empty()) {
            continue;
        }
        
        // Add to list
        symbols.emplace_back(name, lib_base + sym.st_value, sym.st_size, type, bind, vis);
        
        LOG_DBG("Found exported function: %s at 0x%lx (size=%zu)", 
                name.c_str(), lib_base + sym.st_value, sym.st_size);
    }

    // Sort symbols by name for easier lookup
    std::sort(symbols.begin(), symbols.end(),
              [](const auto& a, const auto& b) { return a.name < b.name; });
    
    LOG_DBG("Parsed %zu exported functions from library at 0x%lx", symbols.size(), lib_base);
    return symbols;
}

inline std::map<std::string, uintptr_t> DL_Manager::parse_got_entries(uintptr_t lib_base,
                                                                       const DynamicInfo& info) const {
    std::map<std::string, uintptr_t> got_map;
    
    if (info.jmprel == 0 || info.pltrelsz == 0 || info.pltrel_type != DT_RELA)
        return got_map;

    size_t num_rela = info.pltrelsz / sizeof(Elf64_Rela);
    for (size_t i = 0; i < num_rela; ++i) {
        Elf64_Rela rela;
        uintptr_t rela_addr = info.jmprel + i * sizeof(Elf64_Rela);
        if (!read_struct(pid_, rela_addr, rela)) continue;
        if (ELF64_R_TYPE(rela.r_info) != R_X86_64_JUMP_SLOT) continue;

        uint32_t sym_idx = ELF64_R_SYM(rela.r_info);
        Elf64_Sym sym;
        uintptr_t sym_addr = info.symtab + sym_idx * info.syment;
        if (!read_struct(pid_, sym_addr, sym)) continue;
        if (sym.st_name == 0) continue;

        uintptr_t name_addr = info.strtab + sym.st_name;
        std::string name = read_string(pid_, name_addr, info.strsz);
        if (!name.empty())
            got_map[name] = lib_base + rela.r_offset;
    }
    return got_map;
}

