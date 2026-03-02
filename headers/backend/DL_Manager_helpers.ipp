//=============================================================================
// DL_Manager_helpers.ipp
// Core utility functions used across all modules
//=============================================================================

/**
 * @brief Trim whitespace from both ends of a string
 * @param s Input string
 * @return Trimmed string
 */
static inline std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

/**
 * @brief Normalize library path to absolute form
 * @param path Input path (relative or absolute)
 * @return Absolute path if possible, otherwise original
 * 
 * Converts relative paths to absolute using current working directory.
 * Used to ensure consistent path representation in tracker.
 */
static std::string normalize_path(const std::string& path) {
    if (path.empty()) return path;
    if (path[0] == '/') return path; // Already absolute
    
    // Convert relative to absolute using current working directory
    char* cwd = getcwd(nullptr, 0);
    if (!cwd) return path;
    
    std::string result = std::string(cwd) + "/" + path;
    free(cwd);
    return result;
}

/**
 * @brief Get file information (modification time and size)
 * @param path File path
 * @param mtime [out] Modification time
 * @param size [out] File size
 * @return true if stat succeeded, false otherwise
 */
static bool get_file_info(const std::string& path, time_t& mtime, size_t& size) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        LOG_DBG("stat failed for %s: %s", path.c_str(), strerror(errno));
        return false;
    }
    mtime = st.st_mtime;
    size = st.st_size;
    LOG_DBG("File info for %s: mtime=%ld, size=%zu", path.c_str(), mtime, size);
    return true;
}

/**
 * @brief Read memory from remote process using process_vm_readv
 * @param pid Target process ID
 * @param addr Address to read from
 * @param buffer Local buffer to store data
 * @param size Number of bytes to read
 * @return true if read succeeded, false otherwise
 */
static bool read_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size) {
    struct iovec local = {buffer, size};
    struct iovec remote = {reinterpret_cast<void*>(addr), size};
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    return n == static_cast<ssize_t>(size);
}

/**
 * @brief Read a structure from remote process
 * @param pid Target process ID
 * @param addr Address to read from
 * @param value [out] Structure to fill
 * @return true if read succeeded
 */
template<typename T>
static bool read_struct(pid_t pid, uintptr_t addr, T& value) {
    return read_process_memory(pid, addr, &value, sizeof(T));
}

/**
 * @brief Read a null-terminated string from remote process
 * @param pid Target process ID
 * @param addr Address to read from
 * @param max_len Maximum string length to read
 * @return Read string (empty on failure)
 */
static std::string read_string(pid_t pid, uintptr_t addr, size_t max_len = 256) {
    std::string result;
    char ch;
    for (size_t i = 0; i < max_len; ++i) {
        if (!read_struct(pid, addr + i, ch) || ch == '\0') break;
        result.push_back(ch);
    }
    return result;
}

/**
 * @brief Check if an address is inside any of the given memory segments
 * @param addr Address to check
 * @param segments Vector of [start, end) segment ranges
 * @return true if address is inside any segment
 */
static bool address_in_library(uintptr_t addr, const std::vector<std::pair<uintptr_t, uintptr_t>>& segments) {
    for (const auto& seg : segments) {
        if (addr >= seg.first && addr < seg.second) return true;
    }
    return false;
}
