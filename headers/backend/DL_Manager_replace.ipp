//=============================================================================
// DL_manager_replace.ipp
// Core implementation of library replacement logic
//=============================================================================

//=============================================================================
// Static helper functions (always available, no debug dependencies)
//=============================================================================

/**
 * @brief Log the start of a library replacement operation
 * @param target Target library pattern/name
 * @param new_lib Path to new library
 * @param function Target function to patch ("all" for all functions)
 */
static void log_replacement_start(const std::string& target, const std::string& new_lib, const std::string& function) {
    LOG_RESULT("=== Starting library replacement ===");
    LOG_RESULT("Target pattern: %s", target.c_str());
    LOG_RESULT("New: %s", new_lib.c_str());
    LOG_RESULT("Function: %s", function.c_str());
}

/**
 * @brief Log the result of a library replacement operation
 * @param success True if replacement succeeded, false otherwise
 */
static void log_replacement_result(bool success) {
    if (success) {
        LOG_RESULT("=== Library replacement completed successfully ===");
    } else {
        LOG_RESULT("=== Library replacement failed ===");
    }
}

/**
 * @brief Check if required function addresses are initialized
 * @param dlopen_addr Address of dlopen in target process
 * @param dlclose_addr Address of dlclose in target process
 * @param syscall_insn Address of syscall instruction in target process
 * @return true if all addresses are non-zero
 */
static bool check_required_addresses(uintptr_t dlopen_addr, uintptr_t dlclose_addr, uintptr_t syscall_insn) {
    if (dlopen_addr == 0 || dlclose_addr == 0 || syscall_insn == 0) {
        LOG_ERR("Required addresses not initialized");
        return false;
    }
    return true;
}

/**
 * @brief Start the cleanup daemon on first successful patch
 * 
 * Ensures daemon is running only once to handle cleanup of unused libraries
 */
static void ensure_daemon_running() {
    static bool daemon_started = false;
    if (!daemon_started) {
        if (!Daemon::is_running()) {
            Daemon::start();
        }
        daemon_started = true;
    }
}

//=============================================================================
// DL_Manager implementation
//=============================================================================

/**
 * @brief Initialize addresses of dlopen, dlclose, and syscall in target process
 * 
 * Finds libc.so in target process and locates required symbols and instructions.
 * These addresses are essential for remote code injection.
 */
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

/**
 * @brief Find syscall instruction address in libc
 * @param libc_base Base address of libc in target process
 * @return Address of syscall instruction or 0 if not found
 * 
 * Delegates to architecture-specific implementation.
 */
uintptr_t DL_Manager::find_syscall_instruction(uintptr_t libc_base) {
    return Arch::find_syscall_instruction(this, libc_base);
}

/**
 * @brief Test remote syscall mechanism by executing SYS_GETPID
 * @param tid Thread ID to execute syscall in
 * @return true if syscall executed successfully
 * 
 * Used to verify that the remote syscall mechanism works before attempting
 * to load libraries.
 */
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

/**
 * @brief Validate that target library exists in process memory
 * @param target_lib_pattern Pattern to search for in /proc/pid/maps
 * @param target_info [out] Filled with library information
 * @param clean_path [out] Cleaned path (without leading spaces)
 * @param normalized_path [out] Normalized absolute path
 * @return true if library found and info populated
 */
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

/**
 * @brief Check if it's safe to replace the target library
 * @param normalized_target Normalized path of target library
 * @param target_mtime File modification time
 * @param target_size File size
 * @param target_info_ok Whether file info was successfully obtained
 * @return true if safe to proceed
 * 
 * Updates file info in tracker if changed and logs warnings about active status.
 */
bool DL_Manager::check_target_safety(const std::string& normalized_target,
                                      time_t target_mtime,
                                      size_t target_size,
                                      bool target_info_ok) {
    auto target_it = tracked_libraries_.find(normalized_target);
    if (target_it == tracked_libraries_.end()) {
        LOG_DBG("Target library not in tracker - assuming it's safe to replace");
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

/**
 * @brief Replace target library with new library in the target process
 * @param target_lib_pattern Pattern to identify target library (e.g., "libc.so" or full path)
 * @param new_lib_path Path to the new library file to load
 * @param target_function Function to patch ("all" for all functions, or specific function name)
 * @return true if replacement succeeded, false otherwise
 * 
 * This is the main entry point for library replacement. The function:
 * 1. Validates target library exists in process memory
 * 2. Checks if replacement is safe (threads not using the library)
 * 3. Freezes all threads outside the target library
 * 4. Loads the new library via remote code injection (if not already loaded)
 * 5. Applies patches (JMP or GOT) to redirect functions from old to new library
 * 6. Updates tracker state and saves state to disk
 * 7. Starts cleanup daemon if needed
 * 8. Restores threads and resumes execution
 */
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
    
#ifdef DEBUG
    bool new_info_ok = get_file_info(new_lib_path, new_mtime, new_size);
    LOG_DBG("Target file: path=%s, ok=%d, mtime=%ld, size=%zu", 
            clean_target_path.c_str(), target_info_ok, target_mtime, target_size);
    LOG_DBG("New file: path=%s, ok=%d, mtime=%ld, size=%zu", 
            new_lib_path.c_str(), new_info_ok, new_mtime, new_size);
#else
    get_file_info(new_lib_path, new_mtime, new_size);
#endif

    // Check if target is safe to replace
    if (!check_target_safety(normalized_target, target_mtime, target_size, target_info_ok)) {
        log_replacement_result(false);
        return false;
    }

    // Ensure target is in tracker
    ensure_target_in_tracker(normalized_target, clean_target_path, target_info.base_addr,
                             target_mtime, target_size, target_info_ok);

    // =======================================================================
    // Special case: Switching back to an original library that was previously patched
    // =======================================================================

    auto target_it = tracked_libraries_.find(normalized_target);
    auto new_it = tracked_libraries_.find(normalized_new);

    // Check if we're switching to an original library that has patches
    if (new_it != tracked_libraries_.end() && new_it->second.is_original) {
        if (!new_it->second.saved_original_got.empty() || !new_it->second.saved_original_bytes.empty()) {
            LOG_INFO("Target is original library with existing patches - will restore before applying new patches");
            
            // Get library info for thread safety
            LibraryInfo lib_info = get_library_info(new_lib_path);
            if (lib_info.base_addr == 0) {
                LOG_ERR("Failed to get library info for %s", new_lib_path.c_str());
                log_replacement_result(false);
                return false;
            }
            
            // Get all threads
            std::vector<pid_t> all_tids = get_all_threads(pid_);
            if (all_tids.empty()) {
                LOG_ERR("No threads found");
                log_replacement_result(false);
                return false;
            }
            
            // Freeze threads
            std::vector<ThreadContext> contexts;
            if (!freeze_threads_outside_library(all_tids, lib_info.segments, contexts)) {
                LOG_ERR("Failed to freeze threads for restoration");
                log_replacement_result(false);
                return false;
            }
            
            pid_t worker_tid = contexts[0].tid;
            
            // Restore original code - ТОЛЬКО для target_function
            TrackedLibrary& lib = new_it->second;
            
            // Восстанавливаем ТОЛЬКО указанную функцию
            if (target_function != "all") {
                // Restore GOT entry if exists
                if (lib.saved_original_got.find(target_function) != lib.saved_original_got.end()) {
                    uintptr_t addr = lib.saved_original_got[target_function];
                    uintptr_t got_entry = find_got_entry(lib.base_addr, target_function);
                    if (got_entry != 0) {
                        write_remote_memory(worker_tid, got_entry, &addr, sizeof(addr));
                        LOG_DBG("Restored GOT for %s in original library", target_function.c_str());
                        lib.saved_original_got.erase(target_function);
                    }
                }
                
                // Restore JMP patch if exists
                if (lib.saved_original_bytes.find(target_function) != lib.saved_original_bytes.end()) {
                    auto& bytes = lib.saved_original_bytes[target_function];
                    uintptr_t func_addr = get_symbol_address(lib.base_addr, target_function);
                    if (func_addr != 0 && bytes.size() == 5) {
                        write_remote_memory(worker_tid, func_addr, bytes.data(), 5);
                        LOG_DBG("Restored JMP for %s in original library", target_function.c_str());
                        lib.saved_original_bytes.erase(target_function);
                    }
                }
                
                // Удаляем из patched_functions
                auto pf_it = std::find(lib.patched_functions.begin(), lib.patched_functions.end(), target_function);
                if (pf_it != lib.patched_functions.end()) {
                    lib.patched_functions.erase(pf_it);
                }
            } else {
                // Если "all" - восстанавливаем все функции
                // Restore GOT entries
                for (const auto& [func_name, addr] : lib.saved_original_got) {
                    uintptr_t got_entry = find_got_entry(lib.base_addr, func_name);
                    if (got_entry != 0) {
                        write_remote_memory(worker_tid, got_entry, &addr, sizeof(addr));
                        LOG_DBG("Restored GOT for %s in original library", func_name.c_str());
                    }
                }
                
                // Restore JMP patches
                for (const auto& [func_name, bytes] : lib.saved_original_bytes) {
                    uintptr_t func_addr = get_symbol_address(lib.base_addr, func_name);
                    if (func_addr != 0 && bytes.size() == 5) {
                        write_remote_memory(worker_tid, func_addr, bytes.data(), 5);
                        LOG_DBG("Restored JMP for %s in original library", func_name.c_str());
                    }
                }
                
                lib.patched_functions.clear();
            }
            
            // Save the current state (which is now original) as new backups for future rollbacks
            // Это нужно только для функции, которую мы сейчас патентуем
            if (target_function != "all") {
                uintptr_t func_addr = get_symbol_address(lib.base_addr, target_function);
                if (func_addr != 0) {
                    uint8_t bytes[5];
                    if (read_remote_memory(pid_, func_addr, bytes, 5)) {
                        lib.saved_original_bytes[target_function] = 
                            std::vector<uint8_t>(bytes, bytes + 5);
                        LOG_DBG("Saved current bytes for %s as new backup", target_function.c_str());
                    }
                }
                
                uintptr_t got_entry = find_got_entry(lib.base_addr, target_function);
                if (got_entry != 0) {
                    uintptr_t got_val;
                    if (read_remote_memory(pid_, got_entry, &got_val, sizeof(got_val))) {
                        lib.saved_original_got[target_function] = got_val;
                        LOG_DBG("Saved current GOT for %s as new backup", target_function.c_str());
                    }
                }
            }
            
            // Remove patch references from target libraries - ТОЛЬКО для target_function
            if (target_function != "all") {
                for (const auto& target_path : lib.patched_libraries) {
                    auto target_lib_it = tracked_libraries_.find(target_path);
                    if (target_lib_it != tracked_libraries_.end()) {
                        auto& bwd = target_lib_it->second.patched_by;
                        bwd.erase(std::remove(bwd.begin(), bwd.end(), normalized_new), bwd.end());
                    }
                }
                // Не очищаем весь patched_libraries, только удаляем связи для этой функции
                // Но в текущей архитектуре patched_libraries относится ко всей библиотеке,
                // поэтому лучше оставить как есть или переработать архитектуру
            } else {
                for (const auto& target_path : lib.patched_libraries) {
                    auto target_lib_it = tracked_libraries_.find(target_path);
                    if (target_lib_it != tracked_libraries_.end()) {
                        auto& bwd = target_lib_it->second.patched_by;
                        bwd.erase(std::remove(bwd.begin(), bwd.end(), normalized_new), bwd.end());
                    }
                }
                lib.patched_libraries.clear();
            }
            
            restore_and_detach_all(contexts);
            LOG_INFO("Original library restored for function %s", target_function.c_str());
        }
    }

    // =======================================================================
    // Check library state
    // =======================================================================
    
    uintptr_t new_lib_base = 0, new_handle = 0;
    LoadResult state = check_library_state(new_lib_path, new_lib_base, new_handle, false);
    
    bool need_load = true;
    bool need_patch = true;
    
    switch (state) {
        case LoadResult::ALREADY_ACTIVE:
            LOG_INFO("New library already active and unchanged - applying patches to existing copy");
            need_load = false;
            need_patch = true;
            break;
            
        case LoadResult::CHANGED:
            LOG_INFO("New library file changed - will reload");
            need_load = true;
            need_patch = true;
            break;
            
        case LoadResult::NOT_FOUND:
            LOG_INFO("New library not found in tracker or maps - will load fresh");
            need_load = true;
            need_patch = true;
            break;
            
        case LoadResult::USED_EXISTING:
            LOG_INFO("Using existing library copy (inactive)");
            need_load = false;
            need_patch = true;
            break;
            
        case LoadResult::LOADED_NEW:
            LOG_WARN("Unexpected LOADED_NEW state from check_library_state");
            need_load = false;
            need_patch = true;
            break;
            
        case LoadResult::FAILED:
            LOG_ERR("Failed to check library state");
            log_replacement_result(false);
            return false;
    }

    // =======================================================================
    // Если новая библиотека уже существует и имеет сохранённые патчи,
    // восстанавливаем её в исходное состояние перед использованием
    // =======================================================================
    if (state == LoadResult::USED_EXISTING || state == LoadResult::ALREADY_ACTIVE) {
        auto new_it = tracked_libraries_.find(normalized_new);
        if (new_it != tracked_libraries_.end()) {
            TrackedLibrary& new_lib = new_it->second;
            if (!new_lib.saved_original_got.empty() || !new_lib.saved_original_bytes.empty()) {
                LOG_INFO("New library has existing patches - restoring to original state before use");
                
                // Получаем информацию о сегментах библиотеки для заморозки потоков
                LibraryInfo lib_info = get_library_info(new_lib_path);
                if (lib_info.base_addr == 0) {
                    LOG_ERR("Failed to get library info for %s", new_lib_path.c_str());
                    log_replacement_result(false);
                    return false;
                }
                
                // Замораживаем потоки вне этой библиотеки
                std::vector<pid_t> all_tids = get_all_threads(pid_);
                if (all_tids.empty()) {
                    LOG_ERR("No threads found");
                    log_replacement_result(false);
                    return false;
                }
                
                std::vector<ThreadContext> contexts;
                if (!freeze_threads_outside_library(all_tids, lib_info.segments, contexts)) {
                    LOG_ERR("Failed to freeze threads for restoration");
                    log_replacement_result(false);
                    return false;
                }
                
                pid_t worker_tid = contexts[0].tid;
                
                // Восстанавливаем GOT-записи
                for (const auto& [func_name, addr] : new_lib.saved_original_got) {
                    uintptr_t got_entry = find_got_entry(new_lib.base_addr, func_name);
                    if (got_entry != 0) {
                        if (write_remote_memory(worker_tid, got_entry, &addr, sizeof(addr))) {
                            LOG_DBG("Restored GOT for %s", func_name.c_str());
                        } else {
                            LOG_ERR("Failed to restore GOT for %s", func_name.c_str());
                        }
                    }
                }
                
                // Восстанавливаем JMP-патчи
                for (const auto& [func_name, bytes] : new_lib.saved_original_bytes) {
                    uintptr_t func_addr = get_symbol_address(new_lib.base_addr, func_name);
                    if (func_addr != 0 && bytes.size() == 5) {
                        if (write_remote_memory(worker_tid, func_addr, bytes.data(), 5)) {
                            LOG_DBG("Restored JMP for %s", func_name.c_str());
                            // Сбрасываем кэш инструкций
                        } else {
                            LOG_ERR("Failed to restore JMP for %s", func_name.c_str());
                        }
                    }
                }
                
                // Очищаем списки заплаченных функций и зависимостей
                new_lib.patched_functions.clear();
                new_lib.patched_libraries.clear();
                
                // Удаляем ссылки на эту библиотеку из других (patched_by)
                for (auto& [path, lib] : tracked_libraries_) {
                    auto& bwd = lib.patched_by;
                    bwd.erase(std::remove(bwd.begin(), bwd.end(), normalized_new), bwd.end());
                }
                
                restore_and_detach_all(contexts);
                LOG_INFO("New library restored to clean state");
            }
        }
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

    // Load the library if needed
    if (need_load) {
        LoadResult load_result = ensure_new_library_loaded(worker_tid, normalized_new, 
                                                            new_lib_base, new_handle, saved_regs);
        
        if (load_result == LoadResult::FAILED) {
            LOG_ERR("Failed to load new library");
            restore_and_detach_all(contexts);
            log_replacement_result(false);
            return false;
        }
    }
    
    bool patch_success = true;
    
    // Apply patches if we have a library to patch to
    if (need_patch && new_lib_base != 0) {
        LOG_INFO("Applying patches to %s", 
                 need_load ? "newly loaded library" : "existing library");
        
        patch_success = apply_all_patches(worker_tid, normalized_target, 
                                           target_info.base_addr, new_lib_base,
                                           normalized_new, target_function);
        
        if (patch_success) {
            // Update active status based on function providers
            update_active_status();
            
            // Record the patch relationship (for backward compatibility and cleanup)
            record_patched_library(normalized_new, normalized_target);
            
            // Clean up old libraries (only those with no references)
            cleanup_old_libraries(normalized_target, normalized_new, worker_tid, saved_regs);
            
            // Start daemon if needed
            ensure_daemon_running();
        }
    } else if (!need_patch) {
        LOG_INFO("No patching needed");
        patch_success = true;
    }

    // Restore registers and detach all threads
    restore_and_detach_all(contexts);
    
    log_replacement_result(patch_success);
    return patch_success;
}
