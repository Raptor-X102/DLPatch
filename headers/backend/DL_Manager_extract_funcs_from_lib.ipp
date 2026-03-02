//=============================================================================
// DL_Manager_extract_funcs_from_lib.ipp
// Symbol extraction and filtering
//=============================================================================

/**
 * @brief Find a symbol directly without using cache
 * @param lib_base Base address of library
 * @param sym_name Symbol name to find
 * @return Pointer to new SymbolInfo (caller must delete) or nullptr
 * 
 * This is a slower direct lookup used for one-off symbol queries.
 * For repeated lookups, use cache and get_function_symbols.
 */
const SymbolInfo* DL_Manager::find_symbol_direct(uintptr_t lib_base, const std::string& sym_name) const {
    const SymbolInfo* result = nullptr;

    iterate_dynamic_symbols(pid_, lib_base, [&](const Elf64_Sym& sym, const std::string& name) {
        if (name == sym_name && sym.st_value != 0) {
            int type = ELF64_ST_TYPE(sym.st_info);
            int bind = ELF64_ST_BIND(sym.st_info);
            int vis = ELF64_ST_VISIBILITY(sym.st_other);

            result = new SymbolInfo(name, lib_base + sym.st_value, sym.st_size, type, bind, vis);
            return false; // Stop iteration
        }
        return true; // Continue
    });

    return result;
}

/**
 * @brief Check if a symbol is a patchable exported function
 * @param sym Symbol information
 * @return true if function can be patched, false otherwise
 * 
 * Criteria for patchable functions:
 * - Must be a function (STT_FUNC)
 * - Must have non-zero size (has real code, not PLT stub)
 * - Must be global or weak (exported)
 * - Must have default visibility (not hidden)
 * - Should not be C++ internal runtime symbols
 */
bool DL_Manager::is_exported_function(const SymbolInfo& sym) const {
    // Basic ELF checks for patchable functions
    if (sym.type != STT_FUNC) return false;                          // Must be a function
    if (sym.size == 0) return false;                                 // Must have real code (not PLT stub)
    if (sym.bind != STB_GLOBAL && sym.bind != STB_WEAK) return false; // Must be exported
    if (sym.visibility != STV_DEFAULT) return false;                  // Must not be hidden
    
    // Demangle and filter out C++ standard library symbols
    int status;
    char* demangled = abi::__cxa_demangle(sym.name.c_str(), nullptr, nullptr, &status);
    if (status == 0 && demangled) {
        std::string readable(demangled);
        free(demangled);
        
        // Skip internal C++ runtime symbols
        if (readable.find("std::") == 0 || 
            readable.find("__cxx") != std::string::npos ||
            readable.find("__gnu_cxx") != std::string::npos) {
            LOG_DBG("Skipping C++ runtime symbol: %s", readable.c_str());
            return false;
        }
    }
    
    // Passed all checks - this is a patchable function
    return true;
}

/**
 * @brief Get all patchable function symbols from a library
 * @param lib_base Base address of library
 * @return Vector of SymbolInfo for patchable functions
 * 
 * Uses cache for efficiency. Filters symbols through is_exported_function.
 */
std::vector<SymbolInfo> DL_Manager::get_function_symbols(uintptr_t lib_base) const {
    // Ensure cache is populated for this library
    ensure_cache(lib_base);
    
    std::vector<SymbolInfo> result;
    for (const auto& sym : library_cache_[lib_base].symbols) {
        if (is_exported_function(sym)) {
            result.push_back(sym);
        }
    }
    
    LOG_DBG("Found %zu patchable functions out of %zu total symbols", 
             result.size(), library_cache_[lib_base].symbols.size());
    return result;
}

/**
 * @brief Get address of a symbol
 * @param lib_base Base address of library
 * @param sym_name Symbol name
 * @return Absolute address of symbol, or 0 if not found
 */
uintptr_t DL_Manager::get_symbol_address(uintptr_t lib_base, const std::string& sym_name) const {
    const SymbolInfo* sym = find_symbol_direct(lib_base, sym_name);
    if (!sym) return 0;
    
    uintptr_t addr = sym->addr;
    delete sym;
    return addr;
}

/**
 * @brief Get size of a symbol
 * @param lib_base Base address of library
 * @param sym_name Symbol name
 * @return Size of symbol in bytes, or 0 if not found
 */
size_t DL_Manager::get_symbol_size(uintptr_t lib_base, const std::string& sym_name) const {
    const SymbolInfo* sym = find_symbol_direct(lib_base, sym_name);
    if (!sym) return 0;
    
    size_t size = sym->size;
    delete sym;
    return size;
}
