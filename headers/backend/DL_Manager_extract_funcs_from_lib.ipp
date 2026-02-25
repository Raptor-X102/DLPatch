// DL_Manager_extract_funcs_from_lib.ipp
#include <cstdio>
#include <elf.h>
#include <sys/uio.h>
#include <vector>
#include <cstring>
#include <iostream>
#include <cxxabi.h>

/**
 * Check if a symbol is a patchable exported function
 * @param sym Symbol information to check
 * @return true if the symbol can be patched, false otherwise
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
 * Get all patchable functions from a library
 * @param lib_base Base address of the library
 * @return Vector of symbols that can be safely patched
 */
std::vector<SymbolInfo> DL_Manager::get_function_symbols(uintptr_t lib_base) const {
    ensure_cache(lib_base);
    std::vector<SymbolInfo> result;
    
    for (const auto& sym : library_cache_[lib_base].symbols) {
        if (is_exported_function(sym)) {
            result.push_back(sym);
        }
    }
    
    LOG_INFO("Found %zu patchable functions out of %zu total symbols", 
             result.size(), library_cache_[lib_base].symbols.size());
    return result;
}

/**
 * Get symbol address (only for patchable functions)
 * @param lib_base Base address of the library
 * @param sym_name Name of the symbol
 * @return Address or 0 if not found or not patchable
 */
uintptr_t DL_Manager::get_symbol_address(uintptr_t lib_base, const std::string& sym_name) const {
    const SymbolInfo* sym = find_symbol(lib_base, sym_name);
    if (!sym) return 0;
    
    if (is_exported_function(*sym)) {
        return sym->addr;
    }
    return 0;
}

/**
 * Get symbol size (only for patchable functions)
 * @param lib_base Base address of the library
 * @param sym_name Name of the symbol
 * @return Size or 0 if not found or not patchable
 */
size_t DL_Manager::get_symbol_size(uintptr_t lib_base, const std::string& sym_name) const {
    const SymbolInfo* sym = find_symbol(lib_base, sym_name);
    if (!sym) return 0;
    
    if (is_exported_function(*sym)) {
        return sym->size;
    }
    return 0;
} 

/**
 * Find symbol by name (internal helper)
 * @param lib_base Base address of the library
 * @param sym_name Name of the symbol to find
 * @return Pointer to SymbolInfo or nullptr if not found
 */
const SymbolInfo* DL_Manager::find_symbol(uintptr_t lib_base, const std::string& sym_name) const {
    ensure_cache(lib_base);
    const auto& syms = library_cache_[lib_base].symbols;
    
    for (const auto& s : syms) {
        if (s.name == sym_name) {
            return &s;
        }
    }
    return nullptr;
}
