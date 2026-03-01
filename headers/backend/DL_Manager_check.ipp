// DL_Manager_check.ipp
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <dirent.h>
#include <cstring>
#include <vector>
#include <iostream>
#include <cctype>
#include <fstream>
#include <sstream>
#include <algorithm>

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
