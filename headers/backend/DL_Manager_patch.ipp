//=============================================================================
// DL_Manager_patch.ipp
// Function patching implementation (JMP and GOT redirection)
//=============================================================================

/**
 * @brief Apply a single function patch (either GOT or JMP based on function size)
 * @param tid Thread ID for memory writes
 * @param target_lib_path Path to target library
 * @param old_func Address of function in old library
 * @param new_func Address of function in new library
 * @param old_func_size Size of function in old library
 * @param func_name Name of function being patched
 * @return true if patch succeeded
 * 
 * For small functions (<16 bytes), uses GOT patching.
 * For larger functions (>=16 bytes), uses JMP patching (5-byte relative jump).
 * Saves original bytes/GOT values for potential rollback.
 */
bool DL_Manager::apply_patch(pid_t tid, const std::string& target_lib_path, uintptr_t old_func,
                              uintptr_t new_func, size_t old_func_size,
                  const std::string& func_name) {
    std::string clean_path = trim(target_lib_path);
    auto lib_it = tracked_libraries_.find(clean_path);
    if (lib_it == tracked_libraries_.end()) {
        LOG_ERR("No tracked library for path %s", clean_path.c_str()); 
        return false;
    }
    TrackedLibrary& target_lib = lib_it->second;

    // Threshold for GOT patching (small functions use GOT)
    const size_t THRESHOLD = 16;

    // GOT patch path - for small functions
    if (old_func_size < THRESHOLD) {
        LOG_DBG("Patching %s via GOT (function size: %zu bytes)", 
                 func_name.c_str(), old_func_size);
        
        uintptr_t got_entry = find_got_entry(target_lib.base_addr, func_name);
        if (got_entry == 0) {
            LOG_WARN("No GOT entry for %s", func_name.c_str());
            return false;
        }
        
        // Save original GOT value for rollback
        uintptr_t orig = 0;
        if (!read_remote_memory(pid_, got_entry, &orig, sizeof(orig))) {
            LOG_ERR("Cannot read original GOT");
            return false;
        }
        target_lib.saved_original_got[func_name] = orig;

        // Write new function address to GOT
        if (!write_remote_memory(tid, got_entry, &new_func, sizeof(new_func))) {
            LOG_ERR("GOT write failed");
            return false;
        }
        
        LOG_DBG("GOT patched %s: 0x%lx -> 0x%lx", func_name.c_str(), orig, new_func);
        return true;
    }

    // JMP patch path - for larger functions
    if (old_func_size < 5) {
        LOG_WARN("Function %s too small for JMP patch (%zu bytes)", 
                 func_name.c_str(), old_func_size);
        return false;
    }

    // Save original bytes for rollback
    uint8_t orig_bytes[5];
    if (!read_remote_memory(pid_, old_func, orig_bytes, 5)) {
        LOG_ERR("Cannot read original bytes for %s", func_name.c_str());
        return false;
    }
    target_lib.saved_original_bytes[func_name] = 
        std::vector<uint8_t>(orig_bytes, orig_bytes + 5);
    
    // Create and write JMP patch
    auto patch = Arch::create_jmp_patch(old_func, new_func);
    if (patch.size() != 5) {
        LOG_ERR("Unexpected jmp patch size for %s", func_name.c_str());
        return false;
    }
    
    if (!write_remote_memory(tid, old_func, patch.data(), patch.size())) {
        LOG_ERR("JMP write failed for %s", func_name.c_str());
        return false;
    }
    
    LOG_DBG("JMP patched %s: 0x%lx -> 0x%lx", func_name.c_str(), old_func, new_func);
    return true;
}

/**
 * @brief Apply all function patches between old and new library
 * @param tid Thread ID for memory writes
 * @param target_lib_path Path to target library
 * @param old_base Base address of old library
 * @param new_base Base address of new library
 * @param new_lib_path Path to new library (for tracker updates)
 * @param target_function "all" for all functions, or specific function name
 * @return true if at least one patch succeeded
 * 
 * If target_function is "all", attempts to patch every exported function
 * that exists in both libraries. Otherwise, patches only the specified function.
 * Updates tracker with list of successfully patched functions.
 */
bool DL_Manager::apply_all_patches(pid_t tid, 
                                   const std::string& target_lib_path, 
                                   uintptr_t old_base, 
                                   uintptr_t new_base, 
                                   const std::string& new_lib_path, 
                                   const std::string& target_function) {
    std::string clean_target_path = trim(target_lib_path);
    bool any_success = false;
    int total = 0;
    int succeeded = 0;
    int skipped = 0;
    int failed = 0;
    
    if (target_function == "all") {
        // Get all exported functions from old library
        auto old_symbols = get_function_symbols(old_base);
        LOG_DBG("Found %zu exported functions in old library", old_symbols.size());
        
        std::vector<std::string> patched_functions;
        
        for (const auto& sym : old_symbols) {
            total++;
            const std::string& func_name = sym.name;
            
            // Get function address in new library
            uintptr_t new_func_addr = get_symbol_address(new_base, func_name);
            
            if (new_func_addr == 0) {
                LOG_DBG("Function '%s' not exported in new library, skipping", func_name.c_str());
                skipped++;
                continue;
            }
            
            uintptr_t old_func_addr = sym.addr;
            
            // Apply patch if addresses differ
            if (old_func_addr != new_func_addr) {
                LOG_DBG("Patching %s: 0x%lx -> 0x%lx (size=%zu)", 
                         func_name.c_str(), old_func_addr, new_func_addr, sym.size);
                
                if (apply_patch(tid, target_lib_path, old_func_addr, new_func_addr, sym.size, func_name)) {
                    patched_functions.push_back(func_name);
                    succeeded++;
                    any_success = true;
                } else {
                    LOG_WARN("Failed to patch %s", func_name.c_str());
                    failed++;
                }
            } else {
                LOG_DBG("Function %s already at same address, skipping", func_name.c_str());
                skipped++;
            }
        }
        
        LOG_RESULT("Patching summary: total=%d, succeeded=%d, skipped=%d, failed=%d", 
                   total, succeeded, skipped, failed);
        
        // Update tracker with patched functions
        if (!patched_functions.empty()) {
            tracked_libraries_[new_lib_path].provided_functions = patched_functions;
        }
        
        return any_success;
        
    } else {
        // Patch single function
        uintptr_t old_func = get_symbol_address(old_base, target_function);
        uintptr_t new_func = get_symbol_address(new_base, target_function);
        
        if (old_func == 0) {
            LOG_ERR("Target function '%s' not exported in old library", target_function.c_str());
            return false;
        }
        
        if (new_func == 0) {
            LOG_ERR("Target function '%s' not exported in new library", target_function.c_str());
            return false;
        }
        
        size_t old_size = get_symbol_size(old_base, target_function);
        if (old_size == 0) {
            LOG_WARN("Could not determine size of function '%s', assuming >=5 bytes", 
                     target_function.c_str());
            old_size = 5;
        }
        
        LOG_DBG("Target function at 0x%lx, new at 0x%lx, size=%zu", 
                old_func, new_func, old_size);
        
        if (old_func != new_func) {
            any_success = apply_patch(tid, target_lib_path, old_func, new_func, old_size, target_function);
            if (any_success) {
                tracked_libraries_[new_lib_path].provided_functions.push_back(target_function);
            }
        } else {
            LOG_INFO("Function addresses are identical, no patch needed.");
            any_success = true;
        }
        
        return any_success;
    }
}

/**
 * @brief Clean up old, unused libraries after successful patch
 * @param target_lib_path Path to target library (original)
 * @param new_lib_path Path to new library (replacement)
 * @param tid Thread ID for unload operations
 * @param saved_regs Saved registers for thread
 * 
 * Unloads any libraries that are:
 * - Not the new library
 * - Not original libraries
 * - Inactive (not currently patched to)
 * This prevents memory leaks from accumulating replacement libraries.
 */
void DL_Manager::cleanup_old_libraries(const std::string& target_lib_path,
                                        const std::string& new_lib_path,
                                        pid_t tid,
                                        struct user_regs_struct& saved_regs) {
    LOG_DBG("Cleaning up old libraries...");
    
    std::string normalized_target = target_lib_path;
    std::string normalized_new = new_lib_path;
    
    std::set<std::string> to_unload;
    for (const auto& pair : tracked_libraries_) {
        const TrackedLibrary& lib = pair.second;
        
        // Skip the new library
        if (lib.path == normalized_new) continue;
        
        // Skip original libraries (can't unload them)
        if (lib.is_original) continue;
        
        // Skip if still active (shouldn't happen, but just in case)
        if (lib.is_active) continue;
        
        // This is an inactive non-original library - can unload
        to_unload.insert(pair.first);
    }
    
    for (const std::string& path : to_unload) {
        auto it = tracked_libraries_.find(path);
        if (it != tracked_libraries_.end() && it->second.handle != 0) {
            LOG_INFO("Unloading unused library: %s", path.c_str());
            
            if (unload_library_by_handle(tid, it->second.handle, saved_regs)) {
                invalidate_cache(it->second.base_addr);
                tracked_libraries_.erase(it);
            } else {
                LOG_ERR("Failed to unload %s", path.c_str());
            }
        }
    }
}
