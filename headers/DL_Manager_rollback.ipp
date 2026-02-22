// DL_Manager_rollback.ipp

void resume_all_threads(const std::vector<pid_t>& tids);

bool DL_Manager::rollback_function(const std::string& lib_path, const std::string& func_name) {
    std::string clean_path = trim(lib_path);
    auto it = tracked_libraries_.find(clean_path);
    if (it == tracked_libraries_.end()) {
        LOG_ERR("Library %s not found", clean_path.c_str());
        return false;
    }

    TrackedLibrary& lib = it->second;

    pid_t main_tid;
    struct user_regs_struct saved_regs;
    std::vector<pid_t> tids = stop_threads_and_prepare_main(main_tid, saved_regs);
    if (tids.empty()) return false;

    bool success = false;

    auto got_it = lib.saved_original_got.find(func_name);
    if (got_it != lib.saved_original_got.end()) {
        uintptr_t got_entry = find_got_entry(lib.base_addr, func_name);
        if (got_entry == 0) {
            LOG_ERR("Cannot find GOT entry for %s", func_name.c_str());
        } else if (write_remote_memory(main_tid, got_entry, &got_it->second, sizeof(got_it->second))) {
            LOG_INFO("Rolled back GOT for %s", func_name.c_str());
            lib.saved_original_got.erase(got_it);
            success = true;
        }
    }

    auto jmp_it = lib.saved_original_bytes.find(func_name);
    if (jmp_it != lib.saved_original_bytes.end()) {
        uintptr_t func_addr = get_symbol_address(lib.base_addr, func_name);
        if (func_addr == 0) {
            LOG_ERR("Cannot find function %s", func_name.c_str());
        } else if (jmp_it->second.size() == 5 &&
                   write_remote_memory(main_tid, func_addr, jmp_it->second.data(), 5)) {
            LOG_INFO("Rolled back JMP for %s", func_name.c_str());
            lib.saved_original_bytes.erase(jmp_it);
            success = true;
        }
    }

    resume_all_threads(tids);
    return success;
}

inline bool DL_Manager::rollback_library(const std::string& lib_path) {
    auto it = tracked_libraries_.find(lib_path);
    if (it == tracked_libraries_.end()) {
        LOG_ERR("Library %s not found", lib_path.c_str());
        return false;
    }
    TrackedLibrary& lib = it->second;

    pid_t main_tid;
    struct user_regs_struct saved_regs;
    std::vector<pid_t> tids = stop_threads_and_prepare_main(main_tid, saved_regs);
    if (tids.empty()) return false;

    bool all_ok = true;

    for (auto& p : lib.saved_original_got) {
        uintptr_t got_entry = find_got_entry(lib.base_addr, p.first);
        if (got_entry == 0) {
            LOG_ERR("No GOT entry for %s", p.first.c_str());
            all_ok = false;
        } else if (!write_remote_memory(main_tid, got_entry, &p.second, sizeof(p.second))) {
            LOG_ERR("Failed GOT restore %s", p.first.c_str());
            all_ok = false;
        }
    }

    for (auto& p : lib.saved_original_bytes) {
        uintptr_t func_addr = get_symbol_address(lib.base_addr, p.first);
        if (func_addr == 0) {
            LOG_ERR("No function %s", p.first.c_str());
            all_ok = false;
        } else if (!write_remote_memory(main_tid, func_addr, p.second.data(), p.second.size())) {
            LOG_ERR("Failed JMP restore %s", p.first.c_str());
            all_ok = false;
        }
    }

    if (all_ok) {
        lib.saved_original_got.clear();
        lib.saved_original_bytes.clear();
        lib.is_active = false;
        LOG_INFO("Rolled back all patches for %s", lib_path.c_str());
    } else {
        LOG_WARN("Partial rollback for %s", lib_path.c_str());
    }

    resume_all_threads(tids);
    return all_ok;
}
