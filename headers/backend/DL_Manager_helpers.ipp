#ifndef DL_MANAGER_HELPERS_IPP
#define DL_MANAGER_HELPERS_IPP

#include <sys/uio.h>
#include <cstring>
#include <string>
#include <algorithm>
#include <cctype>
#include <vector>

// Trim whitespace from both ends of a string
static inline std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// Helper to normalize library paths (convert to absolute)
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

// Get file info with debug logging
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

// Functions for reading process memory
static bool read_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size) {
    struct iovec local = {buffer, size};
    struct iovec remote = {reinterpret_cast<void*>(addr), size};
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    return n == static_cast<ssize_t>(size);
}

template<typename T>
static bool read_struct(pid_t pid, uintptr_t addr, T& value) {
    return read_process_memory(pid, addr, &value, sizeof(T));
}

// Read string from process memory
static std::string read_string(pid_t pid, uintptr_t addr, size_t max_len = 256) {
    std::string result;
    char ch;
    for (size_t i = 0; i < max_len; ++i) {
        if (!read_struct(pid, addr + i, ch) || ch == '\0') break;
        result.push_back(ch);
    }
    return result;
}

// Check if address is inside library segments
static bool address_in_library(uintptr_t addr, const std::vector<std::pair<uintptr_t, uintptr_t>>& segments) {
    for (const auto& seg : segments) {
        if (addr >= seg.first && addr < seg.second) return true;
    }
    return false;
}

#endif // DL_MANAGER_HELPERS_IPP
