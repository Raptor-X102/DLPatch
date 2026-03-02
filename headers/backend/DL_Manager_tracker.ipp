// DL_manager_tracker.ipp

void DL_Manager::record_patched_library(const std::string& normalized_new, const std::string& target_path) {
    auto new_lib_it = tracked_libraries_.find(normalized_new);
    if (new_lib_it != tracked_libraries_.end()) {
        // is_active already set in update_active_status
        // Add target to patched_libraries list if not already there
        if (std::find(new_lib_it->second.patched_libraries.begin(), 
                     new_lib_it->second.patched_libraries.end(), 
                     target_path) == new_lib_it->second.patched_libraries.end()) {
            new_lib_it->second.patched_libraries.push_back(target_path);
            LOG_DBG("Recorded patched library %s for %s", target_path.c_str(), normalized_new.c_str());
        }
    }
}

bool DL_Manager::is_library_active(const std::string& lib_path) const {
    auto it = tracked_libraries_.find(lib_path);
    if (it == tracked_libraries_.end()) {
        return false;
    }
    return it->second.is_active;
}

void DL_Manager::update_active_status(const std::string& original_path, const std::string& new_path) {
    // Deactivate original library
    auto orig_it = tracked_libraries_.find(original_path);
    if (orig_it != tracked_libraries_.end()) {
        orig_it->second.is_active = false;
        LOG_DBG("Original library deactivated: %s", original_path.c_str());
    }
    
    // Activate new library
    auto new_it = tracked_libraries_.find(new_path);
    if (new_it != tracked_libraries_.end()) {
        new_it->second.is_active = true;
        LOG_DBG("New library activated: %s", new_path.c_str());
    }
}

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
