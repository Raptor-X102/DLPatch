//=============================================================================
// DL_Manager_check.ipp
// Safety checks for library replacement
//=============================================================================

/**
 * @brief Check if it's safe to replace a library
 * @param lib_name Name or pattern of the library to check
 * @return true if no threads are using the library, false otherwise
 * 
 * Safety means:
 * 1. No thread's instruction pointer is inside the library
 * 2. No thread's stack contains pointers to the library
 * If any thread is using the library, replacement could cause crashes.
 */
bool DL_Manager::is_safe_to_replace(const std::string& lib_name) {
    init_tracker_if_needed();
    
    LibraryInfo info = get_library_info(lib_name);
    if (info.base_addr == 0) {
        LOG_ERR("Library %s not found in process memory", lib_name.c_str());
        return false;
    }
    
    // Get all threads using helper
    std::vector<pid_t> tids = get_threads(pid_);
    
    // Check each thread using helper
    for (pid_t tid : tids) {
        // Skip our own thread if we're attached to the process
        if (tid == gettid()) continue;
        
        if (thread_uses_library(tid, info.segments)) {
            LOG_WARN("Thread %d is inside library %s", tid, lib_name.c_str());
            return false;
        }
    }
    
    LOG_INFO("All threads are outside library %s", lib_name.c_str());
    return true;
}
