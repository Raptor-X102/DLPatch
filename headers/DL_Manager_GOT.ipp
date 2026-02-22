// DL_Manager_got.ipp

uintptr_t DL_Manager::find_got_entry(uintptr_t lib_base, const std::string& sym_name) const {
    ensure_cache(lib_base);
    const auto& got_map = library_cache_[lib_base].got_entries;
    auto it = got_map.find(sym_name);
    if (it != got_map.end()) return it->second;
    LOG_DBG("No GOT entry found for '%s'", sym_name.c_str());
    return 0;
}
