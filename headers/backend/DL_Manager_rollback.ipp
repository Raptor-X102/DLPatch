//=============================================================================
// DL_Manager_rollback.ipp
// Rollback functionality for reverting patches
//=============================================================================

//=============================================================================
// Helper functions for rollback operations
//=============================================================================

/**
 * @brief Validate library exists and has patches to rollback
 * @param lib_path Path to library
 * @param normalized [out] Normalized library path
 * @param lib [out] Reference to tracked library
 * @return true if validation succeeded and library has patches
 */
bool DL_Manager::validate_rollback_library(const std::string& lib_path,
                                           std::string& normalized,
                                           TrackedLibrary*& lib) {
    normalized = normalize_path(lib_path);
    
    auto it = tracked_libraries_.find(normalized);
    if (it == tracked_libraries_.end()) {
        LOG_ERR("Library %s not found in tracker", lib_path.c_str());
        return false;
    }
    
    lib = &it->second;
    
    LOG_DBG("Library %s has GOT backups: %zu, JMP backups: %zu", 
            lib->path.c_str(), lib->saved_original_got.size(), lib->saved_original_bytes.size());

    if (lib->saved_original_got.empty() && lib->saved_original_bytes.empty()) {
        LOG_INFO("No patches found for %s, nothing to rollback", lib->path.c_str());
        return false; // Nothing to rollback
    }
    
    return true;
}

/**
 * @brief Prepare threads for rollback operation
 * @param lib_path Path to library
 * @param contexts [out] Thread contexts for restoration
 * @param worker_tid [out] Selected worker thread ID
 * @return true if preparation succeeded
 */
bool DL_Manager::prepare_for_rollback(const std::string& lib_path,
                                       std::vector<ThreadContext>& contexts,
                                       pid_t& worker_tid) {
    // Get library info for segments
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
    if (!freeze_threads_outside_library(all_tids, lib_info.segments, contexts)) {
        LOG_ERR("Failed to freeze threads for rollback");
        return false;
    }

    worker_tid = contexts[0].tid;
    return true;
}

/**
 * @brief Restore a single GOT entry
 * @param worker_tid Thread ID for memory operations
 * @param lib Library being restored
 * @param func_name Function name
 * @param original_addr Original GOT value
 * @return true if restoration succeeded
 */
bool DL_Manager::restore_got_entry(pid_t worker_tid,
                                    TrackedLibrary& lib,
                                    const std::string& func_name,
                                    uintptr_t original_addr) {
    LOG_DBG("Restoring GOT for %s to 0x%lx", func_name.c_str(), original_addr);
    
    uintptr_t got_entry = find_got_entry(lib.base_addr, func_name);
    if (got_entry == 0) {
        LOG_ERR("No GOT entry found for %s", func_name.c_str());
        return false;
    }
    
    if (!write_remote_memory(worker_tid, got_entry, &original_addr, sizeof(original_addr))) {
        LOG_ERR("Failed to restore GOT for %s", func_name.c_str());
        return false;
    }
    
    LOG_DBG("Successfully restored GOT for %s", func_name.c_str());
    return true;
}

/**
 * @brief Restore a single JMP patch
 * @param worker_tid Thread ID for memory operations
 * @param lib Library being restored
 * @param func_name Function name
 * @param original_bytes Original function bytes
 * @return true if restoration succeeded
 */
bool DL_Manager::restore_jmp_patch(pid_t worker_tid,
                                    TrackedLibrary& lib,
                                    const std::string& func_name,
                                    const std::vector<uint8_t>& original_bytes) {
    LOG_DBG("Restoring JMP for %s (%zu bytes)", func_name.c_str(), original_bytes.size());
    
    uintptr_t func_addr = get_symbol_address(lib.base_addr, func_name);
    if (func_addr == 0) {
        LOG_ERR("No function found for %s", func_name.c_str());
        return false;
    }
    
    if (!write_remote_memory(worker_tid, func_addr, original_bytes.data(), original_bytes.size())) {
        LOG_ERR("Failed to restore JMP for %s", func_name.c_str());
        return false;
    }
    
    LOG_DBG("Successfully restored JMP for %s", func_name.c_str());
    return true;
}

/**
 * @brief Restore all GOT entries in a library
 * @param worker_tid Thread ID for memory operations
 * @param lib Library being restored
 * @param restored_functions [out] List of restored function names
 * @return Number of successfully restored entries
 */
int DL_Manager::restore_all_got_entries(pid_t worker_tid,
                                         TrackedLibrary& lib,
                                         std::vector<std::string>& restored_functions) {
    int restored = 0;
    
    for (auto& p : lib.saved_original_got) {
        if (restore_got_entry(worker_tid, lib, p.first, p.second)) {
            restored_functions.push_back(p.first);
            restored++;
        }
    }
    
    return restored;
}

/**
 * @brief Restore all JMP patches in a library
 * @param worker_tid Thread ID for memory operations
 * @param lib Library being restored
 * @param restored_functions [out] List of restored function names
 * @return Number of successfully restored entries
 */
int DL_Manager::restore_all_jmp_patches(pid_t worker_tid,
                                         TrackedLibrary& lib,
                                         std::vector<std::string>& restored_functions) {
    int restored = 0;
    
    for (auto& p : lib.saved_original_bytes) {
        if (restore_jmp_patch(worker_tid, lib, p.first, p.second)) {
            restored_functions.push_back(p.first);
            restored++;
        }
    }
    
    return restored;
}

/**
 * @brief Clean up after successful rollback
 * @param lib Library that was rolled back
 * @param normalized Normalized library path
 * @param restored_functions List of restored function names
 */
void DL_Manager::cleanup_after_rollback(TrackedLibrary& lib,
                                         const std::string& normalized,
                                         const std::vector<std::string>& restored_functions) {
    // Remove restored functions from function providers map
    for (const auto& func_name : restored_functions) {
        function_providers_.erase(func_name);
        LOG_DBG("Function %s removed from providers map", func_name.c_str());
    }
    
    // Remove patch references from target libraries
    for (const auto& target_path : lib.patched_libraries) {
        auto target_it = tracked_libraries_.find(target_path);
        if (target_it != tracked_libraries_.end()) {
            auto& bwd = target_it->second.patched_by;
            bwd.erase(std::remove(bwd.begin(), bwd.end(), normalized), bwd.end());
        }
    }
    lib.patched_libraries.clear();
    
    // Clear patched functions
    lib.patched_functions.clear();
    
    // Recalculate active status for all libraries
    update_active_status();
}

/**
 * @brief Check if a function has a backup in the library
 * @param lib Library to check
 * @param func_name Function name
 * @param has_got [out] Whether GOT backup exists
 * @param has_jmp [out] Whether JMP backup exists
 */
void DL_Manager::check_function_backup(const TrackedLibrary& lib,
                                        const std::string& func_name,
                                        bool& has_got,
                                        bool& has_jmp) {
    has_got = (lib.saved_original_got.find(func_name) != lib.saved_original_got.end());
    has_jmp = (lib.saved_original_bytes.find(func_name) != lib.saved_original_bytes.end());
}

/**
 * @brief Restore a single function (either GOT or JMP)
 * @param worker_tid Thread ID for memory operations
 * @param lib Library containing the function
 * @param func_name Function name to restore
 * @return true if restoration succeeded
 */
bool DL_Manager::restore_single_function(pid_t worker_tid,
                                          TrackedLibrary& lib,
                                          const std::string& func_name) {
    bool has_got, has_jmp;
    check_function_backup(lib, func_name, has_got, has_jmp);
    
    bool success = false;
    
    if (has_got) {
        auto got_it = lib.saved_original_got.find(func_name);
        if (restore_got_entry(worker_tid, lib, func_name, got_it->second)) {
            lib.saved_original_got.erase(got_it);
            success = true;
        }
    }
    
    if (has_jmp) {
        auto jmp_it = lib.saved_original_bytes.find(func_name);
        if (restore_jmp_patch(worker_tid, lib, func_name, jmp_it->second)) {
            lib.saved_original_bytes.erase(jmp_it);
            success = true;
        }
    }
    
    // Remove from patched_functions if present
    if (success) {
        auto pf_it = std::find(lib.patched_functions.begin(), lib.patched_functions.end(), func_name);
        if (pf_it != lib.patched_functions.end()) {
            lib.patched_functions.erase(pf_it);
        }
    }
    
    return success;
}

/**
 * @brief Rollback all patches applied to a library
 * @param lib_path Path to library to rollback
 * @return true if all patches were successfully reverted
 * 
 * Restores original GOT entries and JMP patches from saved backups.
 * After successful rollback, updates function providers and recalculates active status.
 */
bool DL_Manager::rollback_library(const std::string& lib_path) {
    std::string normalized;
    TrackedLibrary* lib = nullptr;
    
    // Validate library exists and has patches
    if (!validate_rollback_library(lib_path, normalized, lib)) {
        return false; // Error or nothing to rollback
    }

    // Prepare threads for rollback
    std::vector<ThreadContext> contexts;
    pid_t worker_tid = 0;
    if (!prepare_for_rollback(lib_path, contexts, worker_tid)) {
        return false;
    }

    // Restore all patches
    std::vector<std::string> restored_functions;
    int restored_count = 0;
    
    restored_count += restore_all_got_entries(worker_tid, *lib, restored_functions);
    restored_count += restore_all_jmp_patches(worker_tid, *lib, restored_functions);
    
    bool all_ok = (restored_count > 0);

    if (all_ok) {
        cleanup_after_rollback(*lib, normalized, restored_functions);
        LOG_INFO("Successfully rolled back %d patches for %s (backups preserved for future use)", 
                 restored_count, lib->path.c_str());
    } else if (restored_count == 0) {
        LOG_WARN("No patches were restored for %s", lib->path.c_str());
    } else {
        LOG_ERR("Partial rollback: %d of %zu patches restored", 
                restored_count, lib->saved_original_got.size() + lib->saved_original_bytes.size());
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
 * Restores either GOT entry or JMP patch for the specified function.
 * After successful rollback, updates function providers and recalculates active status.
 */
bool DL_Manager::rollback_function(const std::string& lib_path, const std::string& func_name) {
    std::string normalized;
    TrackedLibrary* lib = nullptr;
    
    // Validate library exists
    if (!validate_rollback_library(lib_path, normalized, lib)) {
        return false; // Error or nothing to rollback
    }

    // Check if function has backups
    bool has_got, has_jmp;
    check_function_backup(*lib, func_name, has_got, has_jmp);
    
    if (!has_got && !has_jmp) {
        LOG_INFO("No backups found for function %s in %s", func_name.c_str(), lib_path.c_str());
        return true;
    }

    // Prepare threads for rollback
    std::vector<ThreadContext> contexts;
    pid_t worker_tid = 0;
    if (!prepare_for_rollback(lib_path, contexts, worker_tid)) {
        return false;
    }

    // Restore the single function
    bool success = restore_single_function(worker_tid, *lib, func_name);

    if (success) {
        // Remove from function providers
        function_providers_.erase(func_name);
        LOG_DBG("Function %s removed from providers map, now provided by original library", 
                func_name.c_str());
        
        // Recalculate active status
        update_active_status();
        
        LOG_INFO("Successfully rolled back function %s", func_name.c_str());
    } else {
        LOG_ERR("Failed to rollback function %s", func_name.c_str());
    }

    restore_and_detach_all(contexts);
    return success;
}
