// DL_manager_symbols.ipp
#include <elf.h>
#include <sys/uio.h>
#include <vector>
#include <cstring>
#include <iostream>

// Helper functions for reading remote memory
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

static std::string read_string(pid_t pid, uintptr_t addr, size_t max_len = 256) {
    std::string result;
    char ch;
    for (size_t i = 0; i < max_len; ++i) {
        if (!read_struct(pid, addr + i, ch) || ch == '\0') {
            break;
        }
        result.push_back(ch);
    }
    return result;
}

uintptr_t DL_Manager::get_symbol_address(uintptr_t lib_base, const std::string& sym_name) const {
    // Read ELF header
    Elf64_Ehdr ehdr;
    if (!read_struct(pid_, lib_base, ehdr)) {
        std::cerr << "Failed to read ELF header at 0x" << std::hex << lib_base << std::dec << std::endl;
        return 0;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        std::cerr << "Not a valid ELF file at 0x" << std::hex << lib_base << std::dec << std::endl;
        return 0;
    }

    // Read program headers
    std::vector<Elf64_Phdr> phdrs(ehdr.e_phnum);
    uintptr_t phdr_addr = lib_base + ehdr.e_phoff;
    if (!read_process_memory(pid_, phdr_addr, phdrs.data(), ehdr.e_phnum * sizeof(Elf64_Phdr))) {
        std::cerr << "Failed to read program headers" << std::endl;
        return 0;
    }

    // Find the first LOAD segment with the smallest p_vaddr to compute load bias
    uintptr_t min_p_vaddr = ~0ULL;
    for (const auto& phdr : phdrs) {
        if (phdr.p_type == PT_LOAD && phdr.p_vaddr < min_p_vaddr) {
            min_p_vaddr = phdr.p_vaddr;
        }
    }
    if (min_p_vaddr == ~0ULL) {
        std::cerr << "No LOAD segments found" << std::endl;
        return 0;
    }
    uintptr_t load_bias = lib_base - min_p_vaddr;

    // Find PT_DYNAMIC segment
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
        std::cerr << "No PT_DYNAMIC segment found" << std::endl;
        return 0;
    }

    // Read dynamic section
    size_t dyn_entries = dyn_filesz / sizeof(Elf64_Dyn);
    if (dyn_entries == 0) {
        std::cerr << "Dynamic section size is zero" << std::endl;
        return 0;
    }
    std::vector<Elf64_Dyn> dyn(dyn_entries);
    if (!read_process_memory(pid_, dyn_vaddr, dyn.data(), dyn_filesz)) {
        std::cerr << "Failed to read dynamic section" << std::endl;
        return 0;
    }

    // Extract needed entries
    uintptr_t strtab = 0;
    uintptr_t symtab = 0;
    size_t strsz = 0;
    size_t syment = 0;
    uintptr_t hash = 0;
    uintptr_t gnu_hash = 0;

    for (const auto& d : dyn) {
        switch (d.d_tag) {
            case DT_STRTAB: strtab = d.d_un.d_ptr; break;  // already absolute address
            case DT_SYMTAB: symtab = d.d_un.d_ptr; break;
            case DT_STRSZ:  strsz = d.d_un.d_val; break;
            case DT_SYMENT: syment = d.d_un.d_val; break;
            case DT_HASH:   hash = d.d_un.d_ptr; break;
            case DT_GNU_HASH: gnu_hash = d.d_un.d_ptr; break;
            default: break;
        }
    }

    if (strtab == 0 || symtab == 0 || strsz == 0 || syment == 0) {
        std::cerr << "Missing required dynamic entries (STRTAB, SYMTAB, STRSZ, SYMENT)" << std::endl;
        return 0;
    }

    // Determine number of symbols using either DT_HASH or DT_GNU_HASH
    uint32_t nchain = 0;
    if (hash != 0) {
        uint32_t nbucket;
        if (!read_struct(pid_, hash, nbucket) || !read_struct(pid_, hash + 4, nchain)) {
            std::cerr << "Failed to read hash table header" << std::endl;
            return 0;
        }
    } else if (gnu_hash != 0) {
        // Simple GNU hash handling (for completeness)
        uint32_t nbucket, symoffset, bloom_size, bloom_shift;
        uintptr_t pos = gnu_hash;
        if (!read_struct(pid_, pos, nbucket)) return 0; pos += 4;
        if (!read_struct(pid_, pos, symoffset)) return 0; pos += 4;
        if (!read_struct(pid_, pos, bloom_size)) return 0; pos += 4;
        if (!read_struct(pid_, pos, bloom_shift)) return 0; pos += 4;
        pos += bloom_size * 8; // skip bloom filter (64-bit)
        // Read bucket array
        std::vector<uint32_t> bucket(nbucket);
        if (!read_process_memory(pid_, pos, bucket.data(), nbucket * 4)) return 0;
        // Find maximum chain index
        uint32_t max_chain = 0;
        for (uint32_t b : bucket) if (b > max_chain) max_chain = b;
        // Now read chains until we find a zero entry, but we'll approximate nchain as max_chain + something
        // For simplicity, we'll just iterate until we fail or find symbol; not efficient but works for few symbols.
        // We'll set nchain to a large number and rely on reading symbols until error.
        nchain = 10000; // arbitrary limit, will break on read error
    } else {
        std::cerr << "No hash table found (neither DT_HASH nor DT_GNU_HASH)" << std::endl;
        return 0;
    }

    // Iterate over symbols
    for (uint32_t i = 0; i < nchain; ++i) {
        Elf64_Sym sym;
        uintptr_t sym_addr = symtab + i * syment;
        if (!read_struct(pid_, sym_addr, sym)) {
            break; // probably end of symbol table
        }

        if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC && ELF64_ST_TYPE(sym.st_info) != STT_NOTYPE) {
            continue;
        }
        if (sym.st_name == 0) continue;

        uintptr_t name_addr = strtab + sym.st_name;
        std::string name = read_string(pid_, name_addr, strsz);
        if (name == sym_name) {
            return lib_base + sym.st_value; 
        }
    }

    std::cerr << "Symbol '" << sym_name << "' not found" << std::endl;
    return 0;
}
