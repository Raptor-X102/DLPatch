//=============================================================================
// DL_Manager_get_lib_data.ipp
// Library information retrieval from /proc/pid/maps and tracker management
//=============================================================================

/**
 * @brief Parse /proc/pid/maps to get information about loaded libraries
 * @return Vector of LibraryInfo structures for all loaded libraries
 * 
 * Reads the memory maps of the target process and extracts information about
 * loaded shared libraries (.so files). Each library may have multiple segments
 * which are stored in the segments vector.
 */
std::vector<LibraryInfo> DL_Manager::parse_maps() const {
    std::vector<LibraryInfo> libs;
    std::string maps_path = "/proc/" + std::to_string(pid_) + "/maps";
    std::ifstream file(maps_path);

    if (!file.is_open()) {
        LOG_ERR("Cannot open %s", maps_path.c_str());
        return libs;
    }

    std::map<std::string, LibraryInfo> lib_map;
    std::string line;

    while (std::getline(file, line)) {
        // Skip lines that don't look like shared libraries
        if (line.find(".so") == std::string::npos && 
            line.find(".so.") == std::string::npos) {
            continue;
        }

        std::istringstream iss(line);
        std::string address, perms, offset, dev, inode;
        std::string pathname;

        iss >> address >> perms >> offset >> dev >> inode;
        std::getline(iss, pathname);

        // Clean path (remove leading spaces)
        if (!pathname.empty() && pathname[0] == ' ') pathname = pathname.substr(1);
        
        // Remove " (deleted)" suffix if present
        size_t deleted_pos = pathname.find(" (deleted)");
        if (deleted_pos != std::string::npos) {
            pathname = pathname.substr(0, deleted_pos);
        }
        
        if (pathname.empty()) continue;

        size_t dash = address.find('-');
        if (dash == std::string::npos) continue;

        uintptr_t start = std::stoul(address.substr(0, dash), nullptr, 16);
        uintptr_t end = std::stoul(address.substr(dash + 1), nullptr, 16);

        // Find or create LibraryInfo for this path
        auto it = lib_map.find(pathname);
        if (it != lib_map.end()) {
            it->second.segments.emplace_back(start, end);
            if (start < it->second.base_addr) it->second.base_addr = start;
            if (end > it->second.base_addr + it->second.size) 
                it->second.size = end - it->second.base_addr;
        } else {
            LibraryInfo info(pathname, start, end - start);
            info.segments.emplace_back(start, end);
            lib_map[pathname] = info;
        }
    }

    // Convert map to vector
    for (auto& pair : lib_map) {
        libs.push_back(pair.second);
    }

    return libs;
}

/**
 * @brief Initialize the library tracker if not already done
 * 
 * This function populates the tracker with all libraries currently loaded
 * in the target process. It preserves status information from previously
 * loaded state and marks all newly found libraries as original and active.
 * 
 * The tracker uses multiple path variants (original path, cleaned path,
 * normalized path) to ensure reliable lookup regardless of how a library
 * is referenced.
 */
void DL_Manager::init_tracker_if_needed() {
    if (tracker_initialized_) return;
    
    LOG_DBG("Initializing tracker with all loaded libraries");
    
    auto libs = parse_maps();
    std::set<std::string> processed;
    int added_count = 0;

    for (const auto& lib : libs) {
        // Clean path from leading spaces
        std::string clean_path = lib.path;
        size_t start = clean_path.find_first_not_of(" \t");
        if (start != std::string::npos) {
            clean_path = clean_path.substr(start);
        }
        
        // Try to normalize to absolute path
        char resolved_path[PATH_MAX];
        std::string normalized;
        if (realpath(clean_path.c_str(), resolved_path) != nullptr) {
            normalized = resolved_path;
        } else {
            normalized = clean_path;
        }
        
        LOG_DBG("Processing library: original='%s', clean='%s', normalized='%s'", 
                lib.path.c_str(), clean_path.c_str(), normalized.c_str());
        
        // Check if already in tracker (from loaded state)
        bool found_in_tracker = false;
        TrackedLibrary* existing_lib = nullptr;
        std::string existing_key;
        
        // Check all path variants
        for (const auto& [path, lib_data] : tracked_libraries_) {
            std::string path_norm = normalize_path(path);
            if (path_norm == normalized || path == clean_path || path == lib.path) {
                found_in_tracker = true;
                existing_lib = const_cast<TrackedLibrary*>(&lib_data);
                existing_key = path;
                LOG_DBG("  Library FOUND in tracker (from state): %s", path.c_str());
                LOG_DBG("    Status from state: orig=%d, active=%d", 
                        lib_data.is_original, lib_data.is_active);
                break;
            }
        }
        
        if (found_in_tracker && existing_lib) {
            // Library exists in tracker from state - PRESERVE its status
            LOG_DBG("  Preserving status from state: orig=%d, active=%d",
                    existing_lib->is_original, existing_lib->is_active);
            
            // Update base address if needed
            if (existing_lib->base_addr != lib.base_addr) {
                LOG_DBG("    Updating base address: 0x%lx -> 0x%lx", 
                        existing_lib->base_addr, lib.base_addr);
                existing_lib->base_addr = lib.base_addr;
            }
            
            // Ensure all path variants point to the same library data
            if (normalized != existing_key) {
                tracked_libraries_[normalized] = *existing_lib;
            }
            if (clean_path != normalized && clean_path != existing_key) {
                tracked_libraries_[clean_path] = *existing_lib;
            }
            if (lib.path != clean_path && lib.path != normalized && lib.path != existing_key) {
                tracked_libraries_[lib.path] = *existing_lib;
            }
            
            continue;
        }
        
        // Skip if already processed in this loop
        if (processed.find(normalized) != processed.end()) continue;
        processed.insert(normalized);
        
        // Get file info for change detection
        time_t mtime = 0;
        size_t file_size = 0;
        
        struct stat st;
        if (stat(clean_path.c_str(), &st) == 0) {
            mtime = st.st_mtime;
            file_size = st.st_size;
        } else {
            LOG_DBG("Could not stat %s (normal for some libraries)", clean_path.c_str());
        }
        
        // NEW library - add as original and ACTIVE
        TrackedLibrary tracked(clean_path, 0, lib.base_addr, std::vector<std::string>());
        tracked.is_original = true;
        tracked.is_active = true;  // New libraries are active
        tracked.mtime = mtime;
        tracked.file_size = file_size;
        
        // Store with multiple path variants
        tracked_libraries_[clean_path] = tracked;
        if (normalized != clean_path) {
            tracked_libraries_[normalized] = tracked;
        }
        if (lib.path != clean_path && lib.path != normalized) {
            tracked_libraries_[lib.path] = tracked;
        }
        
        added_count++;
        LOG_DBG("Added NEW original library (ACTIVE): %s", clean_path.c_str());
    }
    
    tracker_initialized_ = true;
    LOG_DBG("Tracker initialized: %d new libraries added, total %zu unique libraries", 
             added_count, tracked_libraries_.size());
}

/**
 * @brief Get list of all loaded libraries with their current status
 * @return Vector of LibraryInfo structures with status information
 * 
 * Combines information from /proc/pid/maps with tracker status
 * (is_original, is_active) to provide a complete picture of loaded libraries.
 * Removes duplicates and returns one entry per unique normalized path.
 */
std::vector<LibraryInfo> DL_Manager::get_loaded_libraries() {
    init_tracker_if_needed();
    
    auto libs = parse_maps();
    std::map<std::string, bool> processed_libs;
    
    // Add status information from tracker
    for (auto& lib : libs) {
        // Clean the path first (remove leading spaces)
        std::string clean_path = lib.path;
        size_t start = clean_path.find_first_not_of(" \t");
        if (start != std::string::npos) {
            clean_path = clean_path.substr(start);
        }
        
        // Try to normalize
        char resolved_path[PATH_MAX];
        std::string normalized;
        if (realpath(clean_path.c_str(), resolved_path) != nullptr) {
            normalized = resolved_path;
        } else {
            normalized = clean_path;
        }
        
        LOG_DBG("Looking for library in tracker: path='%s'", clean_path.c_str());
        
        // Search in tracker
        bool found = false;
        
        // Try all path variants
        for (const auto& [tracker_path, tracker_lib] : tracked_libraries_) {
            std::string tracker_norm = normalize_path(tracker_path);
            if (tracker_norm == normalized || tracker_path == clean_path) {
                lib.is_original = tracker_lib.is_original;
                lib.is_active = tracker_lib.is_active;
                LOG_DBG("  FOUND in tracker: orig=%d, active=%d (from state)", 
                        tracker_lib.is_original, tracker_lib.is_active);
                found = true;
                break;
            }
        }
        
        if (!found) {
            // Should not happen because init_tracker_if_needed adds all libraries
            // But just in case, mark as original and active
            lib.is_original = true;
            lib.is_active = true;
            LOG_DBG("  NOT found in tracker (unexpected) - marking as original ACTIVE");
        }
        
        // For display, use clean path without leading spaces
        lib.path = clean_path;
    }
    
    // Remove duplicates for display (keep one entry per unique normalized path)
    std::map<std::string, LibraryInfo> unique_libs;
    for (auto& lib : libs) {
        std::string norm = normalize_path(lib.path);
        if (unique_libs.find(norm) == unique_libs.end()) {
            unique_libs[norm] = lib;
        }
    }
    
    std::vector<LibraryInfo> result;
    for (auto& [_, lib] : unique_libs) {
        result.push_back(lib);
    }
    
    std::sort(result.begin(), result.end(), 
              [](const LibraryInfo& a, const LibraryInfo& b) {
                  return a.path < b.path;
              });
    
    return result;
}

/**
 * @brief Get information about a specific library by name pattern
 * @param lib_name Pattern to search for in library paths
 * @return LibraryInfo structure (base_addr=0 if not found)
 * 
 * Finds the first library whose path contains the given pattern.
 * Includes status information from tracker.
 */
LibraryInfo DL_Manager::get_library_info(const std::string& lib_name) {
    init_tracker_if_needed();  // Call initialization first
    
    auto all_libs = parse_maps();
    
    for (auto& lib : all_libs) {
        if (lib.path.find(lib_name) != std::string::npos) {
            // Determine status from tracker
            char resolved_path[PATH_MAX];
            std::string normalized;
            if (realpath(lib.path.c_str(), resolved_path) != nullptr) {
                normalized = resolved_path;
            } else {
                normalized = lib.path;
            }
            
            auto it = tracked_libraries_.find(normalized);
            if (it != tracked_libraries_.end()) {
                lib.is_original = it->second.is_original;
                lib.is_active = it->second.is_active;
            } else {
                lib.is_original = true;
                lib.is_active = true;
            }
            
            return lib;
        }
    }
    
    return LibraryInfo();
}

/**
 * @brief Print all loaded libraries with their status
 * 
 * Useful for debugging and user information.
 * Shows path and status (original/replacement, active/inactive).
 */
void DL_Manager::print_loaded_libraries() {
    init_tracker_if_needed();
    
    auto libs = get_loaded_libraries();
    LOG_INFO("Loaded libraries in PID %d:", pid_);
    if (libs.empty()) {
        LOG_INFO("  No libraries found.");
    } else {
        for (const auto& lib : libs) {
            std::string status;
            if (lib.is_original && lib.is_active) {
                status = "original ACTIVE";
            } else if (lib.is_original && !lib.is_active) {
                status = "original INACTIVE";
            } else if (!lib.is_original && lib.is_active) {
                status = "replacement ACTIVE";
            } else if (!lib.is_original && !lib.is_active) {
                status = "replacement INACTIVE";
            } else {
                status = "unknown status";
            }
            LOG_INFO("  %s [%s]", lib.path.c_str(), status.c_str());
        }
    }
}
