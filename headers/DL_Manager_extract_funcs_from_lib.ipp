// DL_Manager_extract_funcs_from_lib.ipp
#include <cstdio>
#include <elf.h>
#include <sys/uio.h>
#include <vector>
#include <cstring>
#include <iostream>

uintptr_t DL_Manager::get_symbol_address(uintptr_t lib_base, const std::string& sym_name) const {
    DynamicInfo info;
    if (!parse_dynamic_info(pid_, lib_base, info)) {
        return 0;
    }

    uint32_t nchain = 0;
    if (info.hash != 0) {
        uint32_t nbucket;
        if (!read_struct(pid_, info.hash, nbucket) || !read_struct(pid_, info.hash + 4, nchain)) {
            LOG_ERR("Failed to read hash table header");
            return 0;
        }
    } else if (info.gnu_hash != 0) {
        nchain = parse_gnu_hash(pid_, info.gnu_hash);
        if (nchain == 0) {
            LOG_WARN("Failed to parse GNU hash, will iterate with limit");
            nchain = 10000;
        }
    } else {
        LOG_WARN("No hash table found, will iterate until read fails");
        nchain = 10000;
    }

    for (uint32_t i = 0; i < nchain; ++i) {
        Elf64_Sym sym;
        uintptr_t sym_addr = info.symtab + i * info.syment;
        if (!read_struct(pid_, sym_addr, sym)) {
            if (i > 0) break;
            continue;
        }
        if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC && ELF64_ST_TYPE(sym.st_info) != STT_NOTYPE) continue;
        if (sym.st_name == 0) continue;

        uintptr_t name_addr = info.strtab + sym.st_name;
        std::string name = read_string(pid_, name_addr, info.strsz);
        if (name == sym_name) {
            return lib_base + sym.st_value;
        }
    }

    LOG_ERR("Symbol '%s' not found", sym_name.c_str());
    return 0;
}

// ============================================================================
// Get all function symbols with their sizes (НОВАЯ ВЕРСИЯ)
// ============================================================================
std::vector<SymbolInfo> DL_Manager::get_function_symbols(uintptr_t lib_base) const {
    std::vector<SymbolInfo> symbols;
    DynamicInfo info;
    if (!parse_dynamic_info(pid_, lib_base, info)) {
        return symbols;
    }

    uint32_t nchain = 0;
    if (info.hash != 0) {
        uint32_t nbucket;
        if (!read_struct(pid_, info.hash, nbucket) || !read_struct(pid_, info.hash + 4, nchain)) {
            LOG_ERR("Failed to read hash table header");
            return symbols;
        }
    } else if (info.gnu_hash != 0) {
        nchain = parse_gnu_hash(pid_, info.gnu_hash);
        if (nchain == 0) {
            LOG_WARN("Failed to parse GNU hash, will iterate with limit");
            nchain = 10000;
        }
    } else {
        LOG_WARN("No hash table found, will iterate until read fails");
        nchain = 10000;
    }

    for (uint32_t i = 0; i < nchain; ++i) {
        Elf64_Sym sym;
        uintptr_t sym_addr = info.symtab + i * info.syment;
        if (!read_struct(pid_, sym_addr, sym)) {
            if (i > 0) break;
            continue;
        }
        if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC) continue;
        if (sym.st_name == 0 || sym.st_value == 0) continue;

        uintptr_t name_addr = info.strtab + sym.st_name;
        std::string name = read_string(pid_, name_addr, info.strsz);
        if (!name.empty()) {
            symbols.emplace_back(name, lib_base + sym.st_value, sym.st_size);
        }
    }

    std::sort(symbols.begin(), symbols.end(),
              [](const auto& a, const auto& b) { return a.name < b.name; });
    return symbols;
}

// ============================================================================
// Get size of a specific symbol
// ============================================================================
size_t DL_Manager::get_symbol_size(uintptr_t lib_base, const std::string& sym_name) const {
    auto symbols = get_function_symbols(lib_base);
    for (const auto& s : symbols) {
        if (s.name == sym_name) return s.size;
    }
    return 0;
} 
