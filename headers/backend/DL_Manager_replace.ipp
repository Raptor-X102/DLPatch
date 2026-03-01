// DL_manager_replace.ipp

//=============================================================================
// Static helper functions 
//=============================================================================

static void log_replacement_start(const std::string& target, const std::string& new_lib, const std::string& function) {
    LOG_RESULT("=== Starting library replacement ===");
    LOG_RESULT("Target pattern: %s", target.c_str());
    LOG_RESULT("New: %s", new_lib.c_str());
    LOG_RESULT("Function: %s", function.c_str());
}

static void log_replacement_result(bool success) {
    if (success) {
        LOG_RESULT("=== Library replacement completed successfully ===");
    } else {
        LOG_RESULT("=== Library replacement failed ===");
    }
}

static bool check_required_addresses(uintptr_t dlopen_addr, uintptr_t dlclose_addr, uintptr_t syscall_insn) {
    if (dlopen_addr == 0 || dlclose_addr == 0 || syscall_insn == 0) {
        LOG_ERR("Required addresses not initialized");
        return false;
    }
    return true;
}

// Start cleanup daemon on first successful patch
static void ensure_daemon_running() {
    static bool daemon_started = false;
    if (!daemon_started) {
        if (!Daemon::is_running()) {
            Daemon::start();
        }
        daemon_started = true;
    }
}

// ============================================================================
// DL_Manager implementation
// ============================================================================

void DL_Manager::init_addresses() {
    LibraryInfo libc_info = get_library_info("libc.so");
    if (libc_info.base_addr == 0) {
        LOG_ERR("Failed to find libc.so in target process - required for dlopen/dlclose");
        return;
    }
    
    dlopen_addr_ = get_symbol_address(libc_info.base_addr, "dlopen");
    dlclose_addr_ = get_symbol_address(libc_info.base_addr, "dlclose");
    syscall_insn_ = find_syscall_instruction(libc_info.base_addr);
    
    if (dlopen_addr_ == 0 || dlclose_addr_ == 0 || syscall_insn_ == 0) {
        LOG_ERR("Failed to locate required symbols in libc");
        return;
    }
    
    LOG_DBG("Initialized addresses: dlopen=0x%lx, dlclose=0x%lx, syscall=0x%lx",
            dlopen_addr_, dlclose_addr_, syscall_insn_);
}

uintptr_t DL_Manager::find_syscall_instruction(uintptr_t libc_base) {
    return Arch::find_syscall_instruction(this, libc_base);
}

bool DL_Manager::test_syscall(pid_t tid) {
    if (syscall_insn_ == 0) return false;
    
    uintptr_t result;
    // Arch::remote_syscall parameters:
    // 1. tid               - thread to execute syscall in
    // 2. result (output)   - will contain syscall return value
    // 3. Arch::SYS_GETPID  - syscall number (39 on x86_64)
    // 4. arg1 (0)          - SYS_GETPID has no arguments, so all are 0
    // 5. arg2 (0)          
    // 6. arg3 (0)          
    // 7. arg4 (0)          
    // 8. arg5 (0)          
    // 9. arg6 (0)          
    // 10. syscall_insn_    - address of "syscall" instruction in remote process
    if (!Arch::remote_syscall(tid, result, Arch::SYS_GETPID, 0, 0, 0, 0, 0, 0, syscall_insn_))
        return false;
    
    return true;
}

bool DL_Manager::validate_target_library(const std::string& target_lib_pattern, 
                                          LibraryInfo& target_info,
                                          std::string& clean_path,
                                          std::string& normalized_path) {
    // Get target library info from /proc/pid/maps
    target_info = get_library_info(target_lib_pattern);
    if (target_info.base_addr == 0) {
        LOG_ERR("Target library not found in process memory");
        return false;
    }

    clean_path = trim(target_info.path);
    normalized_path = normalize_path(clean_path);
    return true;
}

bool DL_Manager::check_target_safety(const std::string& normalized_target,
                                      time_t target_mtime,
                                      size_t target_size,
                                      bool target_info_ok) {
    auto target_it = tracked_libraries_.find(normalized_target);
    if (target_it == tracked_libraries_.end()) {
        LOG_INFO("Target library not in tracker - assuming it's safe to replace");
        return true;
    }

    TrackedLibrary& target_lib = target_it->second;
    
    // Update file info if changed
    update_tracked_file_info(target_lib, target_mtime, target_size, target_info_ok);
    
    // Check if target is original and active - can't unload original
    if (target_lib.is_active && target_lib.is_original) {
        LOG_WARN("Target is original and active - will be patched but cannot be unloaded");
        // This is fine - we can still patch it, just can't unload the original
    }
    else if (target_lib.is_active && !target_lib.is_original) {
        LOG_WARN("Target library is active and non-original. It will be replaced and then unloaded.");
    }
    else if (target_lib.is_original) {
        LOG_INFO("Target is original library - replacement allowed");
    }
    
    return true;
}

//=============================================================================
// Main replacement function 
//=============================================================================
bool DL_Manager::replace_library(const std::string& target_lib_pattern,
                                  const std::string& new_lib_path,
                                  const std::string& target_function) {
    log_replacement_start(target_lib_pattern, new_lib_path, target_function);

    // Check required addresses
    if (!check_required_addresses(dlopen_addr_, dlclose_addr_, syscall_insn_)) {
        log_replacement_result(false);
        return false;
    }

    // Validate target library
    LibraryInfo target_info;
    std::string clean_target_path, normalized_target;
    if (!validate_target_library(target_lib_pattern, target_info, clean_target_path, normalized_target)) {
        log_replacement_result(false);
        return false;
    }

    // Normalize new library path
    std::string normalized_new = normalize_path(new_lib_path);

    // Get file info for change detection
    time_t target_mtime = 0, new_mtime = 0;
    size_t target_size = 0, new_size = 0;
    bool target_info_ok = get_file_info(clean_target_path, target_mtime, target_size);
    bool new_info_ok = get_file_info(new_lib_path, new_mtime, new_size);

    LOG_DBG("Target file: path=%s, ok=%d, mtime=%ld, size=%zu", 
            clean_target_path.c_str(), target_info_ok, target_mtime, target_size);
    LOG_DBG("New file: path=%s, ok=%d, mtime=%ld, size=%zu", 
            new_lib_path.c_str(), new_info_ok, new_mtime, new_size);

    // Check if target is safe to replace
    if (!check_target_safety(normalized_target, target_mtime, target_size, target_info_ok)) {
        log_replacement_result(false);
        return false;
    }

    // Ensure target is in tracker
    ensure_target_in_tracker(normalized_target, clean_target_path, target_info.base_addr,
                             target_mtime, target_size, target_info_ok);

    // =======================================================================
    // EARLY CHECK: Check library state WITHOUT thread
    // =======================================================================
    
    uintptr_t new_lib_base = 0, new_handle = 0;
    LoadResult state = check_library_state(new_lib_path, new_lib_base, new_handle, true);

    if (state == LoadResult::ALREADY_ACTIVE) {
        LOG_INFO("New library already active and unchanged - nothing to do");
        log_replacement_result(true);
        return true;
    }

    if (state == LoadResult::CHANGED) {
        LOG_INFO("New library file changed - will reload");
    }

    // =======================================================================
    // Now we actually need to do real work - freeze threads and inject
    // =======================================================================
    
    // Get all threads
    std::vector<pid_t> all_tids = get_all_threads(pid_);
    if (all_tids.empty()) {
        LOG_ERR("No threads found - process may have terminated");
        log_replacement_result(false);
        return false;
    }

    // Freeze threads outside target library
    std::vector<ThreadContext> contexts;
    if (!freeze_threads_outside_library(all_tids, target_info.segments, contexts)) {
        log_replacement_result(false);
        return false;
    }

    // Select worker thread
    pid_t worker_tid;
    select_worker_thread(contexts, worker_tid);

    // Prepare worker thread for injection
    struct user_regs_struct prepared_regs;
    if (!prepare_thread_for_injection(worker_tid, prepared_regs)) {
        restore_and_detach_all(contexts);
        log_replacement_result(false);
        return false;
    }

    LOG_DBG("Prepared IP=0x%llx, SP=0x%llx", 
            (unsigned long long)Arch::get_ip(prepared_regs), 
            (unsigned long long)Arch::get_sp(prepared_regs));

    struct user_regs_struct saved_regs = prepared_regs;

    // Verify syscall works
    if (!test_syscall(worker_tid)) {
        LOG_ERR("Syscall test failed");
        restore_and_detach_all(contexts);
        log_replacement_result(false);
        return false;
    }

    // Now actually load the library with real thread
    LoadResult load_result = ensure_new_library_loaded(worker_tid, normalized_new, 
                                                        new_lib_base, new_handle, saved_regs);
    
    if (load_result == LoadResult::FAILED) {
        LOG_ERR("Failed to load new library");
        restore_and_detach_all(contexts);
        log_replacement_result(false);
        return false;
    }
    
    bool patch_success = true;
    
    // Apply patches if we have a library to patch to
    if (load_result == LoadResult::LOADED_NEW || load_result == LoadResult::USED_EXISTING) {
        LOG_INFO("Applying patches to %s", 
                 load_result == LoadResult::LOADED_NEW ? "newly loaded library" : "existing library");
        
        patch_success = apply_all_patches(worker_tid, normalized_target, 
                                           target_info.base_addr, new_lib_base,
                                           normalized_new, target_function);
        
        if (patch_success) {
            // Update tracker state - only new library is active now, original becomes inactive
            update_active_status(normalized_target, normalized_new);  // <- Changed from old version
            record_patched_library(normalized_new, target_info.path);
            
            // Clean up old libraries
            cleanup_old_libraries(normalized_target, normalized_new, worker_tid, saved_regs);
            
            // Start daemon if needed
            ensure_daemon_running();
        }
    }

    // Restore registers and detach all threads
    restore_and_detach_all(contexts);
    
    log_replacement_result(patch_success);
    return patch_success;
}
