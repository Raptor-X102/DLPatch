//=============================================================================
// DL_Manager_tracker.ipp
// Library state tracking and status management
//=============================================================================

/**
 * @brief Record that a new library patches the target library
 * @param normalized_new Normalized path of new library (must be key in tracker)
 * @param normalized_target Normalized path of target library (must be key in tracker)
 * 
 * Updates both forward (new -> target) and backward (target -> new) references
 * to track dependencies between libraries. This prevents unloading libraries
 * that are still being referenced by active patches.
 */
void DL_Manager::record_patched_library(const std::string& normalized_new, const std::string& normalized_target) {
    auto new_lib_it = tracked_libraries_.find(normalized_new);
    auto target_it = tracked_libraries_.find(normalized_target);
    
    LOG_DBG("record_patched_library: new='%s' (found=%d), target='%s' (found=%d)",
            normalized_new.c_str(), new_lib_it != tracked_libraries_.end(),
            normalized_target.c_str(), target_it != tracked_libraries_.end());
    
    if (new_lib_it != tracked_libraries_.end() && target_it != tracked_libraries_.end()) {
        // Add forward reference: new library patches target
        if (std::find(new_lib_it->second.patched_libraries.begin(), 
                     new_lib_it->second.patched_libraries.end(), 
                     normalized_target) == new_lib_it->second.patched_libraries.end()) {
            new_lib_it->second.patched_libraries.push_back(normalized_target);
            LOG_DBG("Recorded forward patch: %s -> %s", 
                    normalized_new.c_str(), normalized_target.c_str());
        }
        
        // Add backward reference: target is patched by new library
        if (std::find(target_it->second.patched_by.begin(),
                     target_it->second.patched_by.end(),
                     normalized_new) == target_it->second.patched_by.end()) {
            target_it->second.patched_by.push_back(normalized_new);
            LOG_DBG("Recorded backward patch: %s <- %s", 
                    normalized_target.c_str(), normalized_new.c_str());
        }
    } else {
        LOG_ERR("CRITICAL: Failed to record patch relation: %s -> %s",
                normalized_new.c_str(), normalized_target.c_str());
    }
}

/**
 * @brief Remove patch records when rolling back
 * @param normalized_lib Library being rolled back
 * @param target_path Target library that was patched
 */
void DL_Manager::remove_patch_records(const std::string& normalized_lib, const std::string& target_path) {
    auto lib_it = tracked_libraries_.find(normalized_lib);
    auto target_it = tracked_libraries_.find(target_path);
    
    if (lib_it != tracked_libraries_.end()) {
        // Remove forward reference
        auto& fwd = lib_it->second.patched_libraries;
        fwd.erase(std::remove(fwd.begin(), fwd.end(), target_path), fwd.end());
    }
    
    if (target_it != tracked_libraries_.end()) {
        // Remove backward reference
        auto& bwd = target_it->second.patched_by;
        bwd.erase(std::remove(bwd.begin(), bwd.end(), normalized_lib), bwd.end());
    }
}

/**
 * @brief Check if a library is currently active (patched to)
 * @param lib_path Path to library
 * @return true if library is active
 */
bool DL_Manager::is_library_active(const std::string& lib_path) const {
    auto it = tracked_libraries_.find(lib_path);
    if (it == tracked_libraries_.end()) {
        return false;
    }
    return it->second.is_active;
}

/**
 * @brief Update active status of all libraries based on current function providers
 * 
 * A library is active if:
 * 1. It provides at least one function in function_providers_ map, OR
 * 2. It's an original library that doesn't have any of its functions replaced
 * 
 * This ensures that libraries that provide currently used functions are marked active,
 * and libraries that no longer provide any functions become inactive.
 */
void DL_Manager::update_active_status() {
    LOG_DBG("Updating active status based on function providers");
    
    // First, set all libraries to inactive
    for (auto& [path, lib] : tracked_libraries_) {
        lib.is_active = false;
    }
    
    // For each function in function_providers_, activate its provider library
    for (const auto& [func_name, lib_path] : function_providers_) {
        auto it = tracked_libraries_.find(lib_path);
        if (it != tracked_libraries_.end()) {
            it->second.is_active = true;
            LOG_DBG("  Library %s is active (provides %s)", lib_path.c_str(), func_name.c_str());
        } else {
            LOG_WARN("  Provider library %s for function %s not found in tracker", 
                     lib_path.c_str(), func_name.c_str());
        }
    }
    
    // Also activate original libraries that don't have any of their functions replaced
    for (auto& [path, lib] : tracked_libraries_) {
        if (lib.is_original && !lib.is_active) {
            // Check if any of this library's functions are provided by someone else
            bool has_replaced_functions = false;
            for (const auto& func : lib.provided_functions) {
                if (function_providers_.find(func) != function_providers_.end()) {
                    has_replaced_functions = true;
                    break;
                }
            }
            
            // If none of its functions are replaced, this library is still active
            if (!has_replaced_functions) {
                lib.is_active = true;
                LOG_DBG("  Original library %s is active (no replaced functions)", path.c_str());
            }
        }
    }
    
    // Count active libraries for logging
    int active_count = 0;
    for (const auto& [path, lib] : tracked_libraries_) {
        if (lib.is_active) active_count++;
    }
    LOG_DBG("Active libraries: %d out of %zu", active_count, tracked_libraries_.size());
}

/**
 * @brief Ensure target library is present in tracker (add if missing)
 * @param normalized_target Normalized path of target
 * @param clean_path Cleaned path (for logging)
 * @param target_base Base address of target
 * @param target_mtime File modification time
 * @param target_size File size
 * @param target_info_ok Whether file info was successfully obtained
 * 
 * Adds target as original library if not already tracked.
 * This happens when replacing a library that was loaded by the process
 * before our tracker was initialized.
 */
void DL_Manager::ensure_target_in_tracker(const std::string& normalized_target,
                                           const std::string& clean_path,
                                           uintptr_t target_base,
                                           time_t target_mtime,
                                           size_t target_size,
                                           bool target_info_ok) {
    // Skip if already tracked
    if (tracked_libraries_.find(normalized_target) != tracked_libraries_.end()) {
        return;
    }
    
#ifdef DEBUG
    LOG_DBG("Adding target to tracker: path=%s, base=0x%lx, mtime=%ld, size=%zu, info_ok=%d",
            clean_path.c_str(), target_base, target_mtime, target_size, target_info_ok);
#else
    // Suppress unused parameter warning in release builds
    (void)clean_path;
#endif
    
    // Add as original library
    TrackedLibrary target_lib(normalized_target, 0, target_base, std::vector<std::string>());
    target_lib.is_original = true;
    
    // Store file info - if get_file_info failed, store 0
    target_lib.mtime = target_info_ok ? target_mtime : 0;
    target_lib.file_size = target_info_ok ? target_size : 0;
    
    tracked_libraries_[normalized_target] = target_lib;
    
#ifdef DEBUG
    LOG_DBG("Added target library to tracker: %s", clean_path.c_str());
#endif
}

/**
 * @brief Print current tracker status for debugging
 */
void DL_Manager::print_library_tracker() const {
    LOG_INFO("=== Library Tracker Status ===");
    LOG_INFO("Tracked libraries: %zu", tracked_libraries_.size());
    
    for (const auto& pair : tracked_libraries_) {
        const TrackedLibrary& lib = pair.second;
        std::string status;
        if (lib.is_active) {
            status = "ACTIVE";
        } else if (lib.is_original) {
            status = "ORIGINAL (inactive)";
        } else {
            status = "INACTIVE (can unload)";
        }
        
        LOG_INFO("  Path: %s", lib.path.c_str());
        LOG_INFO("    Handle   : 0x%lx", lib.handle);
        LOG_INFO("    Base     : 0x%lx", lib.base_addr);
        LOG_INFO("    Status   : %s", status.c_str());
        
        if (!lib.provided_functions.empty()) {
            LOG_INFO("    Functions:");
            for (const auto& f : lib.provided_functions) {
                LOG_INFO("      - %s", f.c_str()); 
            }
        } else {
            LOG_INFO("    Functions: (none)");
        }
        
        LOG_INFO("    Patched libs: %zu", lib.patched_libraries.size());
    }
    LOG_INFO("==============================");
}

/**
 * @brief Update tracked file information and detect changes
 * @param lib Library to update
 * @param mtime Current modification time
 * @param size Current file size
 * @param info_ok Whether file info was successfully obtained
 * 
 * Compares current file info with stored values and marks as changed
 * if significant differences detected (size change or mtime change
 * beyond MTIME_TOLERANCE).
 */
void DL_Manager::update_tracked_file_info(TrackedLibrary& lib, time_t mtime, size_t size, bool info_ok) {
    if (!info_ok) {
        LOG_DBG("update_tracked_file_info: no valid info, skipping");
        return;
    }
    
    LOG_DBG("update_tracked_file_info: lib.mtime=%ld, lib.size=%zu, new.mtime=%ld, new.size=%zu",
            lib.mtime, lib.file_size, mtime, size);
    
    // If we don't have valid info in tracker yet, just store it
    if (lib.file_size == 0 && lib.mtime == 0) {
        LOG_DBG("First time getting valid file info for tracked library - storing");
        lib.mtime = mtime;
        lib.file_size = size;
        return;
    }
    
    // Normal case - compare with existing
    bool changed = false;
    
    // Size change is definitive
    if (lib.file_size != size) {
        LOG_DBG("Size changed: %zu -> %zu", lib.file_size, size);
        changed = true;
    }
    // For mtime, only consider significant changes (> tolerance)
    else if (lib.mtime != mtime) {
        time_t diff = llabs(lib.mtime - mtime);
        if (diff > MTIME_TOLERANCE) {
            LOG_DBG("mtime changed significantly: %ld -> %ld (diff=%ld > %ld)", 
                    lib.mtime, mtime, diff, MTIME_TOLERANCE);
            changed = true;
        } else {
            LOG_DBG("mtime changed insignificantly (diff=%ld <= %ld) - ignoring", 
                    diff, MTIME_TOLERANCE);
        }
    }
    
    if (changed) {
        LOG_WARN("Library file has changed on disk since last load");
        lib.mtime = mtime;
        lib.file_size = size;
    } else {
        LOG_DBG("File unchanged");
    }
}
