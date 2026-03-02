//=============================================================================
// DL_Manager_cache.ipp
// Cache management for parsed ELF symbols and GOT entries
//=============================================================================

/**
 * @brief Ensure cache is populated for a given library
 * @param lib_base Base address of the library
 * 
 * Checks if cache exists for this library and is valid.
 * If not, parses dynamic information, symbols, and GOT entries.
 */
void DL_Manager::ensure_cache(uintptr_t lib_base) const {
    auto it = library_cache_.find(lib_base);
    if (it != library_cache_.end() && it->second.parsed)
        return;

    LOG_DBG("Populating cache for library at 0x%lx", lib_base);
    
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

/**
 * @brief Invalidate cache for a specific library or all libraries
 * @param lib_base Base address (0 = clear all)
 */
void DL_Manager::invalidate_cache(uintptr_t lib_base) {
    if (lib_base == 0) {
        library_cache_.clear();
        LOG_DBG("Cleared entire cache");
    } else {
        library_cache_.erase(lib_base);
        LOG_DBG("Invalidated cache for 0x%lx", lib_base);
    }
}

/**
 * @brief Parse all symbols from dynamic section
 * @param lib_base Base address of library
 * @param info Parsed dynamic section information
 * @return Vector of SymbolInfo structures
 * 
 * Iterates through all dynamic symbols, filters out empty ones,
 * and creates SymbolInfo entries with absolute addresses.
 */
std::vector<SymbolInfo> DL_Manager::parse_symbols_from_dynamic(uintptr_t lib_base,
                                                                const DynamicInfo& info) const {
    std::vector<SymbolInfo> symbols;

    iterate_dynamic_symbols(pid_, info, [&](const Elf64_Sym& sym, const std::string& name) {
        if (sym.st_value != 0 && !name.empty()) {
            int type = ELF64_ST_TYPE(sym.st_info);
            int bind = ELF64_ST_BIND(sym.st_info);
            int vis = ELF64_ST_VISIBILITY(sym.st_other);

            symbols.emplace_back(name, lib_base + sym.st_value, sym.st_size, type, bind, vis);
        }
        return true; // Continue to collect all symbols
    });

    // Sort symbols by name for easier lookup
    std::sort(symbols.begin(), symbols.end(),
              [](const auto& a, const auto& b) { return a.name < b.name; });

    LOG_DBG("Parsed %zu symbols from library at 0x%lx", symbols.size(), lib_base);
    return symbols;
}

/**
 * @brief Parse GOT (Global Offset Table) entries from PLT relocations
 * @param lib_base Base address of library
 * @param info Parsed dynamic section information
 * @return Map from symbol name to GOT entry address
 * 
 * Reads PLT relocations (JUMP_SLOT) and maps them to symbol names.
 * GOT entries are used for function address resolution and patching.
 */
std::map<std::string, uintptr_t> DL_Manager::parse_got_entries(uintptr_t lib_base,
                                                                const DynamicInfo& info) const {
    std::map<std::string, uintptr_t> got_map;
    
    if (info.jmprel == 0 || info.pltrelsz == 0 || info.pltrel_type != DT_RELA)
        return got_map;

    size_t num_rela = info.pltrelsz / sizeof(Elf64_Rela);
    for (size_t i = 0; i < num_rela; ++i) {
        Elf64_Rela rela;
        uintptr_t rela_addr = info.jmprel + i * sizeof(Elf64_Rela);
        if (!read_struct(pid_, rela_addr, rela)) continue;
        
        // Only process JUMP_SLOT relocations (PLT entries)
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
