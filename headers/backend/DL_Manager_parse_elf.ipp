#include <elf.h>
#include <vector>
#include <cstring>

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

// GNU hash table parser
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
