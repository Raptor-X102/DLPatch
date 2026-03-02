//=============================================================================
// DL_Manager_rollback.ipp
// Rollback functionality for reverting patches
//=============================================================================

/**
 * @brief Rollback all patches applied to a library
 * @param lib_path Path to library to rollback
 * @return true if all patches were successfully reverted
 * 
 * Restores original GOT entries and JMP patches from saved backups.
 * After successful rollback, the library becomes active again and any
 * replacement library is deactivated.
 */
bool DL_Manager::rollback_library(const std::string& lib_path) {
    std::string normalized = normalize_path(lib_path);
    LOG_INFO("Attempting to rollback library: %s", normalized.c_str());
    
    auto it = tracked_libraries_.find(normalized);
    if (it == tracked_libraries_.end()) {
        LOG_ERR("Library %s not found in tracker", lib_path.c_str());
        return false;
    }
    
    TrackedLibrary& lib = it->second;
    
    LOG_DBG("Library %s has GOT backups: %zu, JMP backups: %zu", 
            lib.path.c_str(), lib.saved_original_got.size(), lib.saved_original_bytes.size());

    if (lib.saved_original_got.empty() && lib.saved_original_bytes.empty()) {
        LOG_INFO("No patches found for %s, nothing to rollback", lib.path.c_str());
        return true;
    }

    // Get library info to obtain segments for thread safety check
    LibraryInfo lib_info = get_library_info(lib_path);
    if (lib_info.base_addr == 0) {
        LOG_ERR("Failed to get library info for %s", lib_path.c_str());
        return false;
    }

    // Get all threads
    std::vector<pid_t> all_tids = get_all_threads(pid_);
    if (all_tids.empty()) {
        LOG_ERR("No threads found - process may have terminated");
        return false;
    }

    // Freeze threads outside this library
    std::vector<ThreadContext> contexts;
    if (!freeze_threads_outside_library(all_tids, lib_info.segments, contexts)) {
        LOG_ERR("Failed to freeze threads for rollback");
        return false;
    }

    // Use first thread as worker (any stopped thread is fine for memory writes)
    pid_t worker_tid = contexts[0].tid;

    bool all_ok = true;
    int restored_count = 0;
    std::string replacement_lib_path;

    // Find the replacement library (active non-original library different from current one)
    for (const auto& [path, l] : tracked_libraries_) {
        if (l.is_active && !l.is_original && path != normalized) {
            replacement_lib_path = path;
            break;
        }
    }

    // Restore GOT entries
    for (auto& p : lib.saved_original_got) {
        LOG_DBG("Restoring GOT for %s to 0x%lx", p.first.c_str(), p.second);
        
        uintptr_t got_entry = find_got_entry(lib.base_addr, p.first);
        if (got_entry == 0) {
            LOG_ERR("No GOT entry found for %s", p.first.c_str());
            all_ok = false;
            continue;
        }
        
        if (!write_remote_memory(worker_tid, got_entry, &p.second, sizeof(p.second))) {
            LOG_ERR("Failed to restore GOT for %s", p.first.c_str());
            all_ok = false;
            continue;
        }
        
        restored_count++;
        LOG_DBG("Successfully restored GOT for %s", p.first.c_str());
    }

    // Restore JMP patches
    for (auto& p : lib.saved_original_bytes) {
        LOG_DBG("Restoring JMP for %s (%zu bytes)", p.first.c_str(), p.second.size());
        
        uintptr_t func_addr = get_symbol_address(lib.base_addr, p.first);
        if (func_addr == 0) {
            LOG_ERR("No function found for %s", p.first.c_str());
            all_ok = false;
            continue;
        }
        
        if (!write_remote_memory(worker_tid, func_addr, p.second.data(), p.second.size())) {
            LOG_ERR("Failed to restore JMP for %s", p.first.c_str());
            all_ok = false;
            continue;
        }
        
        restored_count++;
        LOG_DBG("Successfully restored JMP for %s", p.first.c_str());
    }

    if (all_ok && restored_count > 0) {
        lib.saved_original_got.clear();
        lib.saved_original_bytes.clear();
        lib.is_active = true;
        
        if (!replacement_lib_path.empty()) {
            auto replacement_it = tracked_libraries_.find(replacement_lib_path);
            if (replacement_it != tracked_libraries_.end()) {
                replacement_it->second.is_active = false;
                LOG_DBG("Replacement library deactivated: %s", replacement_lib_path.c_str());
            }
        }
        
        LOG_INFO("Successfully rolled back %d patches for %s", restored_count, lib.path.c_str());
    } else if (restored_count == 0) {
        LOG_WARN("No patches were restored for %s", lib.path.c_str());
    } else {
        LOG_ERR("Partial rollback: %d of %zu patches restored", 
                restored_count, lib.saved_original_got.size() + lib.saved_original_bytes.size());
    }

    restore_and_detach_all(contexts);
    return all_ok;
}

/**
 * @brief Rollback a single function patch
 * @param lib_path Path to library containing the function
 * @param func_name Name of function to rollback
 * @return true if patch was successfully reverted
 * 
 * Restores either GOT entry or JMP patch for the specified function,
 * depending on which type of patch was originally applied.
 */
bool DL_Manager::rollback_function(const std::string& lib_path, const std::string& func_name) {
    std::string normalized = normalize_path(lib_path);
    LOG_INFO("Attempting to rollback function %s from %s", func_name.c_str(), lib_path.c_str());

    auto it = tracked_libraries_.find(normalized);
    if (it == tracked_libraries_.end()) {
        LOG_ERR("Library %s not found in tracker", lib_path.c_str());
        return false;
    }

    TrackedLibrary& lib = it->second;

    bool has_got = (lib.saved_original_got.find(func_name) != lib.saved_original_got.end());
    bool has_jmp = (lib.saved_original_bytes.find(func_name) != lib.saved_original_bytes.end());
    
    if (!has_got && !has_jmp) {
        LOG_INFO("No backups found for function %s in %s", func_name.c_str(), lib_path.c_str());
        return true;
    }

    // Get library info for segments
    LibraryInfo lib_info = get_library_info(lib_path);
    if (lib_info.base_addr == 0) {
        LOG_ERR("Failed to get library info for %s", lib_path.c_str());
        return false;
    }

    std::vector<pid_t> all_tids = get_all_threads(pid_);
    if (all_tids.empty()) {
        LOG_ERR("No threads found");
        return false;
    }

    std::vector<ThreadContext> contexts;
    if (!freeze_threads_outside_library(all_tids, lib_info.segments, contexts)) {
        LOG_ERR("Failed to freeze threads for rollback");
        return false;
    }

    pid_t worker_tid = contexts[0].tid;
    bool success = false;

    if (has_got) {
        auto got_it = lib.saved_original_got.find(func_name);
        LOG_DBG("Restoring GOT for %s to 0x%lx", func_name.c_str(), got_it->second);
        
        uintptr_t got_entry = find_got_entry(lib.base_addr, func_name);
        if (got_entry == 0) {
            LOG_ERR("Cannot find GOT entry for %s", func_name.c_str());
        } else if (write_remote_memory(worker_tid, got_entry, &got_it->second, sizeof(got_it->second))) {
            LOG_INFO("Successfully rolled back GOT for %s", func_name.c_str());
            lib.saved_original_got.erase(got_it);
            success = true;
        } else {
            LOG_ERR("Failed to write GOT for %s", func_name.c_str());
        }
    }

    if (has_jmp) {
        auto jmp_it = lib.saved_original_bytes.find(func_name);
        LOG_DBG("Restoring JMP for %s (%zu bytes)", func_name.c_str(), jmp_it->second.size());
        
        uintptr_t func_addr = get_symbol_address(lib.base_addr, func_name);
        if (func_addr == 0) {
            LOG_ERR("Cannot find function %s", func_name.c_str());
        } else if (jmp_it->second.size() == 5 &&
                   write_remote_memory(worker_tid, func_addr, jmp_it->second.data(), 5)) {
            LOG_INFO("Successfully rolled back JMP for %s", func_name.c_str());
            lib.saved_original_bytes.erase(jmp_it);
            success = true;
        } else {
            LOG_ERR("Failed to write JMP for %s", func_name.c_str());
        }
    }

    restore_and_detach_all(contexts);
    
    if (success) {
        LOG_INFO("Successfully rolled back function %s", func_name.c_str());
    } else {
        LOG_ERR("Failed to rollback function %s", func_name.c_str());
    }
    
    return success;
}
