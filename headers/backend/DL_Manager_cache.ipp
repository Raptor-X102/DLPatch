// DL_Manager_cache.ipp
#include <algorithm>

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

void DL_Manager::invalidate_cache(uintptr_t lib_base) {
    if (lib_base == 0) {
        library_cache_.clear();
        LOG_DBG("Cleared entire cache");
    } else {
        library_cache_.erase(lib_base);
        LOG_DBG("Invalidated cache for 0x%lx", lib_base);
    }
}

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
