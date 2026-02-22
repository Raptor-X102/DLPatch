// DL_Manager_extract_funcs_from_lib.ipp
#include <cstdio>
#include <elf.h>
#include <sys/uio.h>
#include <vector>
#include <cstring>
#include <iostream>

uintptr_t DL_Manager::get_symbol_address(uintptr_t lib_base, const std::string& sym_name) const {
    ensure_cache(lib_base);
    const auto& syms = library_cache_[lib_base].symbols;
    for (const auto& s : syms) {
        if (s.name == sym_name) return s.addr;
    }
    LOG_ERR("Symbol %s not found", sym_name.c_str());
    return 0;
}

// ============================================================================
// Get all function symbols with their sizes (НОВАЯ ВЕРСИЯ)
// ============================================================================
std::vector<SymbolInfo> DL_Manager::get_function_symbols(uintptr_t lib_base) const {
    ensure_cache(lib_base);
    return library_cache_[lib_base].symbols;
}

// ============================================================================
// Get size of a specific symbol
// ============================================================================
size_t DL_Manager::get_symbol_size(uintptr_t lib_base, const std::string& sym_name) const {
    ensure_cache(lib_base);
    const auto& syms = library_cache_[lib_base].symbols;
    for (const auto& s : syms) {
        if (s.name == sym_name) return s.size;
    }
    return 0;
} 
