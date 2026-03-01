LoadResult DL_Manager::check_library_state(const std::string& lib_path,
                                            uintptr_t& base, 
                                            uintptr_t& handle,
                                            bool check_active_only) {
    std::string normalized = normalize_path(lib_path);
    
    LOG_DBG("check_library_state: %s", lib_path.c_str());
    
    // Get current file info
    time_t current_mtime = 0;
    size_t current_size = 0;
    bool file_info_ok = get_file_info(lib_path, current_mtime, current_size);
    
    // Check if we have it in tracker
    auto it = tracked_libraries_.find(normalized);
    if (it == tracked_libraries_.end()) {
        // Not in tracker - check if it's in maps (loaded by process)
        uintptr_t maps_base = 0;
        if (is_library_in_maps(lib_path, maps_base)) {
            LOG_DBG("  not in tracker but found in maps at 0x%lx", maps_base);
            base = maps_base;
            handle = 0;  // No handle for process-loaded libraries
            return LoadResult::USED_EXISTING;
        }
        LOG_DBG("  not found anywhere");
        return LoadResult::NOT_FOUND;
    }
    
    TrackedLibrary& lib = it->second;
    LOG_DBG("  in tracker: base=0x%lx, handle=0x%lx, active=%d, mtime=%ld, size=%zu",
            lib.base_addr, lib.handle, lib.is_active, lib.mtime, lib.file_size);
    
    // Check if file changed
    bool file_changed = false;
    if (file_info_ok && lib.file_size != 0) {
        if (lib.file_size != current_size) {
            LOG_DBG("  size changed: %zu -> %zu", lib.file_size, current_size);
            file_changed = true;
        } else if (lib.mtime != current_mtime) {
            time_t diff = llabs(lib.mtime - current_mtime);
            if (diff > MTIME_TOLERANCE) {
                LOG_DBG("  mtime changed: %ld -> %ld", lib.mtime, current_mtime);
                file_changed = true;
            }
        }
    } else if (file_info_ok && lib.file_size == 0) {
        // First time getting valid info - update tracker
        LOG_DBG("  first time getting valid file info");
        lib.mtime = current_mtime;
        lib.file_size = current_size;
    }
    
    if (file_changed) {
        LOG_DBG("  file changed, needs reload");
        base = lib.base_addr;
        handle = lib.handle;
        return LoadResult::CHANGED;
    }
    
    if (check_active_only && lib.is_active) {
        LOG_DBG("  already active and unchanged");
        base = lib.base_addr;
        handle = lib.handle;
        return LoadResult::ALREADY_ACTIVE;
    }
    
    LOG_DBG("  exists but inactive or no active check");
    base = lib.base_addr;
    handle = lib.handle;
    return LoadResult::USED_EXISTING;
}

LoadResult DL_Manager::ensure_new_library_loaded(pid_t tid,
                                                  const std::string& new_lib_path,
                                                  uintptr_t& new_lib_base,
                                                  uintptr_t& new_handle,
                                                  struct user_regs_struct& saved_regs) {
    if (tid == 0) {
        LOG_ERR("ensure_new_library_loaded called with tid=0");
        return LoadResult::FAILED;
    }
    
    std::string normalized = normalize_path(new_lib_path);
    
    LOG_DBG("ensure_new_library_loaded: %s (tid=%d)", new_lib_path.c_str(), tid);
    
    // Get current file info
    time_t current_mtime = 0;
    size_t current_size = 0;
    bool file_info_ok = get_file_info(new_lib_path, current_mtime, current_size);
    
    // Check if library is already loaded in process memory
    uintptr_t existing_base = 0;
    bool in_maps = is_library_in_maps(new_lib_path, existing_base);
    
    // Check if we have it in tracker
    auto it = tracked_libraries_.find(normalized);
    bool in_tracker = (it != tracked_libraries_.end());
    
    // Case 1: Not in tracker and not in maps - load fresh
    if (!in_tracker && !in_maps) {
        LOG_INFO("Library not loaded, loading fresh copy");
        new_lib_base = load_new_library(tid, new_lib_path, new_handle, saved_regs);
        if (new_lib_base == 0) return LoadResult::FAILED;
        
        TrackedLibrary& lib = tracked_libraries_[normalized];
        lib = TrackedLibrary(normalized, new_handle, new_lib_base, "");
        lib.mtime = file_info_ok ? current_mtime : 0;
        lib.file_size = file_info_ok ? current_size : 0;
        
        LOG_DBG("  loaded fresh: base=0x%lx, handle=0x%lx", new_lib_base, new_handle);
        return LoadResult::LOADED_NEW;
    }
    
    // Case 2: In tracker - check if file changed and handle reload
    if (in_tracker) {
        TrackedLibrary& lib = it->second;
        
        // Check if file has changed
        bool file_changed = false;
        if (file_info_ok && lib.file_size != 0) {
            if (lib.file_size != current_size) {
                LOG_DBG("  size changed: %zu -> %zu", lib.file_size, current_size);
                file_changed = true;
            } else if (lib.mtime != current_mtime) {
                time_t diff = llabs(lib.mtime - current_mtime);
                if (diff > MTIME_TOLERANCE) {
                    LOG_DBG("  mtime changed: %ld -> %ld", lib.mtime, current_mtime);
                    file_changed = true;
                }
            }
        }
        
        if (!file_changed) {
            // File unchanged - use existing
            LOG_INFO("Library already loaded and unchanged, using existing copy");
            new_lib_base = lib.base_addr;
            new_handle = lib.handle;
            return LoadResult::USED_EXISTING;
        } else {
            // File changed, need to reload
            LOG_INFO("Library file changed, reloading");
            
            if (lib.is_active && lib.is_original) {
                LOG_ERR("Cannot reload active original library");
                return LoadResult::FAILED;
            }
            
            // Load new version first
            uintptr_t temp_handle = 0, temp_base = 0;
            temp_base = load_new_library(tid, new_lib_path, temp_handle, saved_regs);
            if (temp_base == 0) return LoadResult::FAILED;
            
            // Unload old version
            if (lib.handle != 0) {
                LOG_DBG("  unloading old version with handle 0x%lx", lib.handle);
                unload_library_by_handle(tid, lib.handle, saved_regs);
            }
            
            // Update tracker
            lib.handle = temp_handle;
            lib.base_addr = temp_base;
            lib.provided_functions.clear();
            lib.mtime = current_mtime;
            lib.file_size = current_size;
            
            new_lib_base = temp_base;
            new_handle = temp_handle;
            
            LOG_INFO("Library reloaded successfully");
            return LoadResult::LOADED_NEW;
        }
    }
    
    // Case 3: In maps but not in tracker (loaded by process itself)
    if (in_maps && !in_tracker) {
        LOG_INFO("Library loaded by process but not tracked, loading our copy");
        
        new_lib_base = load_new_library(tid, new_lib_path, new_handle, saved_regs);
        if (new_lib_base == 0) return LoadResult::FAILED;
        
        TrackedLibrary& lib = tracked_libraries_[normalized];
        lib = TrackedLibrary(normalized, new_handle, new_lib_base, "");
        lib.mtime = file_info_ok ? current_mtime : 0;
        lib.file_size = file_info_ok ? current_size : 0;
        
        LOG_INFO("Library loaded and tracked");
        return LoadResult::LOADED_NEW;
    }
    
    return LoadResult::FAILED;
}

bool DL_Manager::check_preconditions(const std::string& target_lib_pattern) {
    if (!is_safe_to_replace(target_lib_pattern)) {
        LOG_ERR("Not safe to replace library: threads are using it");
        return false;
    }
    
    if (dlopen_addr_ == 0 || dlclose_addr_ == 0 || syscall_insn_ == 0) {
        LOG_ERR("Required addresses not initialized. Call init_addresses() first.");
        return false;
    }
    
    return true;
}
