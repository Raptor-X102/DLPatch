// DL_Manager_got.ipp

uintptr_t DL_Manager::find_got_entry(uintptr_t lib_base, const std::string& sym_name) const {
    DynamicInfo info;
    if (!parse_dynamic_info(pid_, lib_base, info)) {
        return 0;
    }

    if (info.jmprel == 0 || info.pltrelsz == 0) {
        LOG_DBG("No JMPREL/PLTRELSZ in dynamic section");
        return 0;
    }

    if (info.pltrel_type != DT_RELA) {
        LOG_WARN("Unsupported PLT relocation type (expected DT_RELA), got %lu", info.pltrel_type);
        return 0;
    }

    size_t num_rela = info.pltrelsz / sizeof(Elf64_Rela);
    for (size_t i = 0; i < num_rela; ++i) {
        Elf64_Rela rela;
        uintptr_t rela_addr = info.jmprel + i * sizeof(Elf64_Rela);
        if (!read_struct(pid_, rela_addr, rela)) {
            LOG_ERR("Failed to read relocation entry %zu", i);
            continue;
        }

        if (ELF64_R_TYPE(rela.r_info) != R_X86_64_JUMP_SLOT) continue;

        uint32_t sym_idx = ELF64_R_SYM(rela.r_info);
        Elf64_Sym sym;
        uintptr_t sym_addr = info.symtab + sym_idx * info.syment;
        if (!read_struct(pid_, sym_addr, sym)) {
            LOG_ERR("Failed to read symbol %u", sym_idx);
            continue;
        }
        if (sym.st_name == 0) continue;

        uintptr_t name_addr = info.strtab + sym.st_name;
        std::string name = read_string(pid_, name_addr, info.strsz);
        if (name == sym_name) {
            uintptr_t got_entry = lib_base + rela.r_offset;
            LOG_DBG("Found GOT entry for '%s' at 0x%lx (offset 0x%lx)",
                    sym_name.c_str(), got_entry, rela.r_offset);
            return got_entry;
        }
    }

    LOG_DBG("No GOT entry found for '%s'", sym_name.c_str());
    return 0;
}
