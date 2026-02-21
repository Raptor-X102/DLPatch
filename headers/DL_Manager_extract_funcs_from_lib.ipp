// DL_Manager_extract_funcs_from_lib.ipp
#include <cstdio>
#include <elf.h>
#include <sys/uio.h>
#include <vector>
#include <cstring>
#include <iostream>

static bool read_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size) {
    struct iovec local = {buffer, size};
    struct iovec remote = {reinterpret_cast<void*>(addr), size};
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    return n == static_cast<ssize_t>(size);
}

template<typename T>
static bool read_struct(pid_t pid, uintptr_t addr, T& value) {
    return read_process_memory(pid, addr, &value, sizeof(T));
}

// ============================================================================
// GNU hash table parser
// Returns the maximum symbol index + 1, or 0 on failure.
// ============================================================================
static uint32_t parse_gnu_hash(pid_t pid, uintptr_t gnu_hash_addr) {
    // Header: nbucket, symoffset, bloom_size, bloom_shift
    uint32_t header[4];
    if (!read_process_memory(pid, gnu_hash_addr, header, sizeof(header))) {
        LOG_DBG("Failed to read GNU hash header");
        return 0;
    }
    uint32_t nbucket = header[0];
    uint32_t symoffset = header[1];
    uint32_t bloom_size = header[2];
    // uint32_t bloom_shift = header[3]; // not needed

    // Address of bucket array
    uintptr_t bucket_addr = gnu_hash_addr + 16 + bloom_size * 8; // 64-bit bloom
    // Address of chain array
    uintptr_t chain_addr = bucket_addr + nbucket * 4;

    uint32_t max_idx = symoffset - 1; // symbols before symoffset exist, but we don't have chain info for them
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
            if (chain_val & 1) break; // last in chain
            ++j;
        }
    }
    return max_idx + 1; // total symbols count
}

static std::string read_string(pid_t pid, uintptr_t addr, size_t max_len = 256) {
    std::string result;
    char ch;
    for (size_t i = 0; i < max_len; ++i) {
        if (!read_struct(pid, addr + i, ch) || ch == '\0') break;
        result.push_back(ch);
    }
    return result;
}

uintptr_t DL_Manager::get_symbol_address(uintptr_t lib_base, const std::string& sym_name) const {
    Elf64_Ehdr ehdr;
    if (!read_struct(pid_, lib_base, ehdr)) {
        LOG_ERR("Failed to read ELF header at 0x%lx", lib_base);
        return 0;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        LOG_ERR("Not a valid ELF file at 0x%lx", lib_base);
        return 0;
    }

    std::vector<Elf64_Phdr> phdrs(ehdr.e_phnum);
    uintptr_t phdr_addr = lib_base + ehdr.e_phoff;
    if (!read_process_memory(pid_, phdr_addr, phdrs.data(), ehdr.e_phnum * sizeof(Elf64_Phdr))) {
        LOG_ERR("Failed to read program headers");
        return 0;
    }

    uintptr_t min_p_vaddr = ~0ULL;
    for (const auto& phdr : phdrs) {
        if (phdr.p_type == PT_LOAD && phdr.p_vaddr < min_p_vaddr) min_p_vaddr = phdr.p_vaddr;
    }
    if (min_p_vaddr == ~0ULL) {
        LOG_ERR("No LOAD segments found");
        return 0;
    }
    uintptr_t load_bias = lib_base - min_p_vaddr;

    uintptr_t dyn_vaddr = 0;
    size_t dyn_filesz = 0;
    for (const auto& phdr : phdrs) {
        if (phdr.p_type == PT_DYNAMIC) {
            dyn_vaddr = load_bias + phdr.p_vaddr;
            dyn_filesz = phdr.p_filesz;
            break;
        }
    }
    if (dyn_vaddr == 0) {
        LOG_ERR("No PT_DYNAMIC segment found");
        return 0;
    }

    size_t dyn_entries = dyn_filesz / sizeof(Elf64_Dyn);
    if (dyn_entries == 0) {
        LOG_ERR("Dynamic section size is zero");
        return 0;
    }
    std::vector<Elf64_Dyn> dyn(dyn_entries);
    if (!read_process_memory(pid_, dyn_vaddr, dyn.data(), dyn_filesz)) {
        LOG_ERR("Failed to read dynamic section");
        return 0;
    }

    uintptr_t strtab = 0, symtab = 0;
    size_t strsz = 0, syment = 0;

    for (const auto& d : dyn) {
        switch (d.d_tag) {
            case DT_STRTAB: strtab = d.d_un.d_ptr; break;
            case DT_SYMTAB: symtab = d.d_un.d_ptr; break;
            case DT_STRSZ:  strsz = d.d_un.d_val; break;
            case DT_SYMENT: syment = d.d_un.d_val; break;
            default: break;
        }
    }

    if (strtab == 0 || symtab == 0 || strsz == 0 || syment == 0) {
        LOG_ERR("Missing required dynamic entries (STRTAB, SYMTAB, STRSZ, SYMENT)");
        return 0;
    }

    const uint32_t MAX_SYMBOLS = 50000;
    for (uint32_t i = 0; i < MAX_SYMBOLS; ++i) {
        Elf64_Sym sym;
        uintptr_t sym_addr = symtab + i * syment;
        if (!read_struct(pid_, sym_addr, sym)) break;

        if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC && ELF64_ST_TYPE(sym.st_info) != STT_NOTYPE) continue;
        if (sym.st_name == 0) continue;

        uintptr_t name_addr = strtab + sym.st_name;
        std::string name = read_string(pid_, name_addr, strsz);
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
    
    Elf64_Ehdr ehdr;
    if (!read_struct(pid_, lib_base, ehdr)) {
        LOG_ERR("Failed to read ELF header at 0x%lx", lib_base);
        return symbols;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        LOG_ERR("Not a valid ELF file at 0x%lx", lib_base);
        return symbols;
    }

    std::vector<Elf64_Phdr> phdrs(ehdr.e_phnum);
    uintptr_t phdr_addr = lib_base + ehdr.e_phoff;
    if (!read_process_memory(pid_, phdr_addr, phdrs.data(), ehdr.e_phnum * sizeof(Elf64_Phdr))) {
        LOG_ERR("Failed to read program headers");
        return symbols;
    }

    uintptr_t min_p_vaddr = ~0ULL;
    for (const auto& phdr : phdrs) {
        if (phdr.p_type == PT_LOAD && phdr.p_vaddr < min_p_vaddr) min_p_vaddr = phdr.p_vaddr;
    }
    if (min_p_vaddr == ~0ULL) {
        LOG_ERR("No LOAD segments found");
        return symbols;
    }
    uintptr_t load_bias = lib_base - min_p_vaddr;

    uintptr_t dyn_vaddr = 0;
    size_t dyn_filesz = 0;
    for (const auto& phdr : phdrs) {
        if (phdr.p_type == PT_DYNAMIC) {
            dyn_vaddr = load_bias + phdr.p_vaddr;
            dyn_filesz = phdr.p_filesz;
            break;
        }
    }
    if (dyn_vaddr == 0) {
        LOG_ERR("No PT_DYNAMIC segment found");
        return symbols;
    }

    size_t dyn_entries = dyn_filesz / sizeof(Elf64_Dyn);
    if (dyn_entries == 0) return symbols;
    
    std::vector<Elf64_Dyn> dyn(dyn_entries);
    if (!read_process_memory(pid_, dyn_vaddr, dyn.data(), dyn_filesz)) {
        LOG_ERR("Failed to read dynamic section");
        return symbols;
    }

    uintptr_t strtab = 0, symtab = 0;
    size_t strsz = 0, syment = 0;
    uintptr_t hash = 0;
    uintptr_t gnu_hash = 0;

    for (const auto& d : dyn) {
        switch (d.d_tag) {
            case DT_STRTAB: strtab = d.d_un.d_ptr; break;
            case DT_SYMTAB: symtab = d.d_un.d_ptr; break;
            case DT_STRSZ:  strsz = d.d_un.d_val; break;
            case DT_SYMENT: syment = d.d_un.d_val; break;
            case DT_HASH:   hash = d.d_un.d_ptr; break;
            case DT_GNU_HASH: gnu_hash = d.d_un.d_ptr; break;
            default: break;
        }
    }

    if (strtab == 0 || symtab == 0 || strsz == 0 || syment == 0) {
        LOG_ERR("Missing required dynamic entries");
        return symbols;
    }

    uint32_t nchain = 0;
    if (hash != 0) {
        uint32_t nbucket;
        if (!read_struct(pid_, hash, nbucket) || !read_struct(pid_, hash + 4, nchain)) {
            LOG_ERR("Failed to read hash table header");
            return symbols;
        }
    } else if (gnu_hash != 0) {
        nchain = parse_gnu_hash(pid_, gnu_hash);
        if (nchain == 0) {
            LOG_WARN("Failed to parse GNU hash, will iterate with limit");
            nchain = 10000;
        }
    } else {
        LOG_WARN("No hash table found (neither DT_HASH nor DT_GNU_HASH), will iterate until read fails");
        nchain = 10000;
    }

    for (uint32_t i = 0; i < nchain; ++i) {
        Elf64_Sym sym;
        uintptr_t sym_addr = symtab + i * syment;
        if (!read_struct(pid_, sym_addr, sym)) {
            if (i > 0) break;
            continue;
        }

        if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC) continue;
        if (sym.st_name == 0 || sym.st_value == 0) continue;

        uintptr_t name_addr = strtab + sym.st_name;
        std::string name = read_string(pid_, name_addr, strsz);
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
