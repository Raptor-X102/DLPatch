//=============================================================================
// DL_Manager_GOT.ipp
// GOT (Global Offset Table) entry lookup
//=============================================================================

/**
 * @brief Find GOT entry address for a symbol
 * @param lib_base Base address of library
 * @param sym_name Symbol name
 * @return Address of GOT entry, or 0 if not found
 * 
 * Uses cache for efficiency. GOT entries are used for PLT-based function
 * calls and can be patched to redirect function calls.
 */
uintptr_t DL_Manager::find_got_entry(uintptr_t lib_base, const std::string& sym_name) const {
    ensure_cache(lib_base);
    const auto& got_map = library_cache_[lib_base].got_entries;
    auto it = got_map.find(sym_name);
    if (it != got_map.end()) return it->second;
    LOG_DBG("No GOT entry found for '%s'", sym_name.c_str());
    return 0;
}
