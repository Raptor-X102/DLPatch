//=============================================================================
// frontend.ipp
// Implementation of the Frontend class - user interface to DL_Manager
//=============================================================================

#include "frontend.hpp"
#include "daemon.hpp"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <unistd.h>
#include <sys/wait.h>

//=============================================================================
// Construction / Destruction
//=============================================================================

/**
 * @brief Construct a new Frontend object
 * @param pid Target process PID
 * 
 * Initializes DL_Manager and attempts to load saved state for this PID.
 */
Frontend::Frontend(pid_t pid) : pid_(pid), mgr_(pid) {
    state_path_ = get_state_path();
    bool state_loaded = load_state();
    if (state_loaded) {
        LOG_DBG("State loaded successfully for PID %d", pid_);
    } else {
        LOG_DBG("No state found for PID %d, starting fresh", pid_);
    }
}

//=============================================================================
// State file management
//=============================================================================

/**
 * @brief Get the path to the state file for this PID
 * @return Full path to JSON state file
 * 
 * Creates ~/.dl_manager/state/ directory if it doesn't exist.
 */
std::string Frontend::get_state_path() const {
    const char* home = getenv("HOME");
    if (!home) {
        const char* sudo_user = getenv("SUDO_USER");
        if (sudo_user) {
            struct passwd* pw = getpwnam(sudo_user);
            if (pw) home = pw->pw_dir;
        }
    }
    if (!home) {
        struct passwd* pw = getpwuid(getuid());
        home = pw ? pw->pw_dir : ".";
    }
    
    std::string base_dir = std::string(home) + "/.dl_manager";
    std::string state_dir = base_dir + "/state";
    
    // Create directories if they don't exist
    if (mkdir(base_dir.c_str(), 0700) != 0 && errno != EEXIST) {
        LOG_ERR("Failed to create directory %s: %s", base_dir.c_str(), strerror(errno));
    }
    if (mkdir(state_dir.c_str(), 0700) != 0 && errno != EEXIST) {
        LOG_ERR("Failed to create directory %s: %s", state_dir.c_str(), strerror(errno));
    }
    
    return state_dir + "/" + std::to_string(pid_) + ".json";
}

/**
 * @brief Convert pointer to hex string for JSON serialization
 * @param ptr Pointer value
 * @return Hex string with "0x" prefix
 */
std::string Frontend::ptr_to_hex(uintptr_t ptr) {
    std::stringstream ss;
    ss << "0x" << std::hex << ptr;
    return ss.str();
}

/**
 * @brief Convert hex string to pointer value
 * @param hex Hex string (with or without "0x" prefix)
 * @return Pointer value
 */
uintptr_t Frontend::hex_to_ptr(const std::string& hex) {
    if (hex.size() > 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
        return std::stoull(hex.substr(2), nullptr, 16);
    return std::stoull(hex, nullptr, 16);
}

/**
 * @brief Convert byte vector to hex string for JSON serialization
 * @param bytes Vector of bytes
 * @return Hex string without prefix
 */
std::string Frontend::bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : bytes)
        ss << std::setw(2) << (int)b;
    return ss.str();
}

/**
 * @brief Convert hex string to byte vector
 * @param hex Hex string (even length)
 * @return Vector of bytes
 */
std::vector<uint8_t> Frontend::hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
        bytes.push_back(std::stoi(hex.substr(i, 2), nullptr, 16));
    return bytes;
}

/**
 * @brief Save current state to JSON file
 * @return true if save succeeded
 * 
 * Serializes tracked libraries, their status, and all backup data
 * (GOT entries and JMP patch bytes) for later restoration.
 */
bool Frontend::save_state() const {
    std::string path = get_state_path();
    std::ofstream f(path);
    if (!f.is_open()) {
        LOG_ERR("Failed to open state file for writing: %s", path.c_str());
        LOG_ERR("Error: %s", strerror(errno));
        return false;
    }
    
    json j;
    j["pid"] = pid_;
    j["tracked_libraries"] = json::array();

    auto libs = mgr_.get_tracked_libraries();
    LOG_DBG("Saving state for PID %d with %zu libraries", pid_, libs.size());
    
    for (const auto& [path, lib] : libs) {
        json item;
        item["path"] = lib.path;
        item["handle"] = ptr_to_hex(lib.handle);
        item["base_addr"] = ptr_to_hex(lib.base_addr);
        item["is_original"] = lib.is_original;
        item["is_active"] = lib.is_active;
        item["patched_functions"] = lib.patched_functions;
        item["provided_functions"] = lib.provided_functions;
        item["patched_libraries"] = lib.patched_libraries;

        LOG_DBG("  Saving library %s:", lib.path.c_str());
        LOG_DBG("    GOT backups: %zu", lib.saved_original_got.size());
        LOG_DBG("    JMP backups: %zu", lib.saved_original_bytes.size());

        json got;
        for (const auto& [f, a] : lib.saved_original_got) {
            got[f] = ptr_to_hex(a);
            LOG_DBG("      GOT %s -> 0x%lx", f.c_str(), a);
        }
        item["saved_original_got"] = got;

        json bytes;
        for (const auto& [f, v] : lib.saved_original_bytes) {
            bytes[f] = bytes_to_hex(v);
            LOG_DBG("      JMP %s (%zu bytes)", f.c_str(), v.size());
        }
        item["saved_original_bytes"] = bytes;

        j["tracked_libraries"].push_back(item);
    }

    f << j.dump(4);
    if (!f.good()) {
        LOG_ERR("Failed to write state file");
        return false;
    }
    
    LOG_DBG("State saved to %s", path.c_str());
    return true;
}

/**
 * @brief Load state from JSON file
 * @return true if load succeeded
 * 
 * Restores tracked libraries and all backup data from saved state.
 * Creates normalized path aliases for reliable lookups.
 */
bool Frontend::load_state() {
    std::ifstream f(state_path_);
    if (!f.is_open()) {
        LOG_DBG("No state file found at %s", state_path_.c_str());
        return false;
    }

    json j;
    try {
        f >> j;
        if (!j.contains("pid") || j["pid"] != pid_) {
            LOG_WARN("State file PID mismatch or invalid format");
            return false;
        }

        std::map<std::string, TrackedLibrary> loaded_libs;

        LOG_DBG("Loading state for PID %d", pid_);
        
        for (const auto& item : j["tracked_libraries"]) {
            TrackedLibrary lib;
            lib.path = item.value("path", "");
            lib.handle = hex_to_ptr(item.value("handle", "0"));
            lib.base_addr = hex_to_ptr(item.value("base_addr", "0"));
            lib.is_original = item.value("is_original", false);
            lib.is_active = item.value("is_active", false);

            LOG_DBG("  Loading library %s: orig=%d, active=%d", 
                    lib.path.c_str(), lib.is_original, lib.is_active);

            if (item.contains("patched_functions"))
                lib.patched_functions = item["patched_functions"].get<std::vector<std::string>>();
            if (item.contains("provided_functions"))
                lib.provided_functions = item["provided_functions"].get<std::vector<std::string>>();
            if (item.contains("patched_libraries"))
                lib.patched_libraries = item["patched_libraries"].get<std::vector<std::string>>();

            if (item.contains("saved_original_got")) {
                for (auto& [key, val] : item["saved_original_got"].items()) {
                    lib.saved_original_got[key] = hex_to_ptr(val);
                }
            }
            
            if (item.contains("saved_original_bytes")) {
                for (auto& [key, val] : item["saved_original_bytes"].items()) {
                    lib.saved_original_bytes[key] = hex_to_bytes(val);
                }
            }

            LOG_DBG("    GOT backups: %zu", lib.saved_original_got.size());
            LOG_DBG("    JMP backups: %zu", lib.saved_original_bytes.size());
            
            // Store by original path
            loaded_libs[lib.path] = lib;
            
            // Also create normalized alias for lookups
            char resolved_path[PATH_MAX];
            if (realpath(lib.path.c_str(), resolved_path) != nullptr) {
                std::string normalized = resolved_path;
                if (normalized != lib.path) {
                    loaded_libs[normalized] = lib;
                    LOG_DBG("    Added normalized alias: %s", normalized.c_str());
                }
            }
        }
        
        mgr_.set_tracked_libraries(loaded_libs);
        LOG_DBG("Loaded %zu libraries from state (with aliases: %zu total entries)", 
                 j["tracked_libraries"].size(), loaded_libs.size());
        return true;
    } catch (const std::exception& e) {
        LOG_ERR("Failed to parse state file: %s", e.what());
        return false;
    }
}

//=============================================================================
// Daemon management
//=============================================================================

/**
 * @brief Ensure the cleanup daemon is running
 * @return true if daemon is running (or started successfully)
 * 
 * Forks and executes the daemon if it's not already running.
 */
bool Frontend::ensure_daemon_running() const {
    if (Daemon::is_running())
        return true;

    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        execlp("dl_manager_daemon", "dl_manager_daemon", "start", nullptr);
        exit(1);
    }
    waitpid(pid, nullptr, 0);
    return Daemon::is_running();
}

//=============================================================================
// Public command implementations
//=============================================================================

/**
 * @brief List all loaded libraries in the target process
 * @return true on success
 * 
 * Displays library paths and their status (original/replacement, active/inactive).
 */
bool Frontend::list_libraries() const {
    auto libs = mgr_.get_loaded_libraries();
    
    if (libs.empty()) {
        std::cout << "No libraries found in process " << pid_ << "\n";
        return true;
    }
    
    std::cout << "Libraries loaded in process " << pid_ << ":\n";
    std::cout << "----------------------------------------\n";
    
    for (const auto& lib : libs) {
        std::string status;
        if (lib.is_original && lib.is_active) {
            status = "original ACTIVE (patched to)";
        } else if (lib.is_original && !lib.is_active) {
            status = "original INACTIVE (not patched to)";
        } else if (!lib.is_original && lib.is_active) {
            status = "replacement ACTIVE (patched to)";
        } else if (!lib.is_original && !lib.is_active) {
            status = "replacement INACTIVE (unused)";
        } else {
            status = "unknown status";
        }
        
        std::cout << std::left << std::setw(60) << lib.path 
                  << " [" << status << "]\n";
    }
    
    std::cout << "----------------------------------------\n";
    
    // Show tracker contents for debugging
    auto tracked = mgr_.get_tracked_libraries();
    std::cout << "\nTracker contents (" << tracked.size() << " libraries):\n";
    for (const auto& [path, lib] : tracked) {
        std::cout << "  " << path << ": orig=" << lib.is_original 
                  << ", active=" << lib.is_active << "\n";
    }
    
    return true;
}

/**
 * @brief List all exported functions in a library
 * @param pattern Pattern to identify the library
 * @return true on success
 */
bool Frontend::list_symbols(const std::string& pattern) const {
    LibraryInfo info = mgr_.get_library_info(pattern);
    if (info.base_addr == 0) {
        std::cerr << "Library not found: " << pattern << '\n';
        return false;
    }

    auto syms = mgr_.get_function_symbols(info.base_addr);
    if (syms.empty()) {
        std::cout << "No function symbols found.\n";
        return true;
    }

    for (const auto& s : syms) {
        std::cout << s.name << " @ 0x" << std::hex << s.addr
                  << " size=" << std::dec << s.size << '\n';
    }
    return true;
}

/**
 * @brief Replace a library in the target process
 * @param target Target library pattern
 * @param new_lib Path to new library
 * @param func Function to patch ("all" for all functions)
 * @return true if replacement succeeded
 */
bool Frontend::replace_library(const std::string& target, const std::string& new_lib, const std::string& func) {
    LOG_INFO("Replacing library: target=%s, new=%s, func=%s", 
             target.c_str(), new_lib.c_str(), func.c_str());
    
    bool ok = mgr_.replace_library(target, new_lib, func);
    
    if (ok) {
        LOG_INFO("Replacement successful.");
        
#ifdef DEBUG
        // Debug-only detailed backup information
        auto tracked = mgr_.get_tracked_libraries();
        std::string target_norm = normalize_path(target);
        std::string new_norm = normalize_path(new_lib);
        
        LOG_DBG("Checking saved backup data:");
        
        auto target_it = tracked.find(target_norm);
        if (target_it != tracked.end()) {
            LOG_DBG("  Target library %s:", target_norm.c_str());
            LOG_DBG("    GOT backups: %zu", target_it->second.saved_original_got.size());
            LOG_DBG("    JMP backups: %zu", target_it->second.saved_original_bytes.size());
            
            for (const auto& [fname, val] : target_it->second.saved_original_got) {
                LOG_DBG("      GOT: %s -> 0x%lx", fname.c_str(), val);
            }
            for (const auto& [fname, bytes] : target_it->second.saved_original_bytes) {
                LOG_DBG("      JMP: %s (%zu bytes)", fname.c_str(), bytes.size());
            }
        }
        
        auto new_it = tracked.find(new_norm);
        if (new_it != tracked.end()) {
            LOG_DBG("  New library %s:", new_norm.c_str());
            LOG_DBG("    is_active: %d", new_it->second.is_active);
            LOG_DBG("    patched_functions: %zu", new_it->second.patched_functions.size());
        }
#endif
        
        save_state();
        ensure_daemon_running();
        LOG_DBG("State saved after replacement");
    } else {
        LOG_ERR("Replacement failed");
    }
    
    return ok;
}

/**
 * @brief Rollback all patches applied to a library
 * @param lib Path to library
 * @return true if rollback succeeded
 */
bool Frontend::rollback_library(const std::string& lib) {
    auto tracked = mgr_.get_tracked_libraries();
    
    LOG_DBG("Tracked libraries for PID %d:", pid_);
    
    std::string search_normalized = normalize_path(lib);
    LOG_DBG("Searching for normalized path: %s", search_normalized.c_str());
    
    std::string found_path;
    TrackedLibrary* found_lib = nullptr;
    
    for (auto& [path, lib_data] : tracked) {
        std::string path_normalized = normalize_path(path);
        
        LOG_DBG("  %s (norm=%s, GOT=%zu, JMP=%zu)", 
                path.c_str(), 
                path_normalized.c_str(),
                lib_data.saved_original_got.size(), 
                lib_data.saved_original_bytes.size());
        
        if (path_normalized == search_normalized) {
            found_path = path;
            found_lib = &lib_data;
            LOG_DBG("Found matching library: %s", path.c_str());
            LOG_DBG("  GOT backups: %zu, JMP backups: %zu", 
                    lib_data.saved_original_got.size(), 
                    lib_data.saved_original_bytes.size());
        }
    }
    
    if (!found_lib) {
        LOG_ERR("Library not found in tracker: %s", lib.c_str());
        return false;
    }
    
    if (found_lib->saved_original_got.empty() && found_lib->saved_original_bytes.empty()) {
        LOG_INFO("No patches to rollback for %s", found_path.c_str());
        return true;
    }
    
    bool ok = mgr_.rollback_library(found_path);
    if (ok) {
        LOG_INFO("Successfully rolled back library: %s", found_path.c_str());
        save_state();
    } else {
        LOG_ERR("Failed to rollback library: %s", found_path.c_str());
    }
    return ok;
}

/**
 * @brief Rollback a single function patch
 * @param lib Path to library
 * @param func Function name
 * @return true if rollback succeeded
 */
bool Frontend::rollback_function(const std::string& lib, const std::string& func) {
    auto tracked = mgr_.get_tracked_libraries();
    
    std::string search_norm = normalize_path(lib);
    std::string found_path;
    
    for (const auto& [path, lib_data] : tracked) {
        if (normalize_path(path) == search_norm) {
            found_path = path;
            
            bool has_got = (lib_data.saved_original_got.find(func) != lib_data.saved_original_got.end());
            bool has_jmp = (lib_data.saved_original_bytes.find(func) != lib_data.saved_original_bytes.end());
            
            if (!has_got && !has_jmp) {
                LOG_ERR("Function '%s' not found in backups for library %s", 
                        func.c_str(), path.c_str());
                return false;
            }
            break;
        }
    }
    
    if (found_path.empty()) {
        LOG_ERR("Library not found in tracker: %s", lib.c_str());
        return false;
    }
    
    bool ok = mgr_.rollback_function(found_path, func);
    if (ok) {
        LOG_INFO("Successfully rolled back function %s from %s", func.c_str(), found_path.c_str());
        save_state();
    } else {
        LOG_ERR("Failed to rollback function %s from %s", func.c_str(), found_path.c_str());
    }
    return ok;
}

/**
 * @brief Unload a library from the target process
 * @param lib Path to library
 * @return true if unload succeeded
 * 
 * Only non-original, inactive libraries can be unloaded.
 */
bool Frontend::unload_library(const std::string& lib) {
    bool ok = mgr_.unload_library(lib);
    if (ok) save_state();
    return ok;
}

/**
 * @brief Print detailed status of tracked libraries
 */
void Frontend::print_status() const {
    auto libs = mgr_.get_tracked_libraries();
    if (libs.empty()) {
        std::cout << "No tracked libraries for PID " << pid_ << '\n';
        return;
    }

    for (const auto& [path, lib] : libs) {
        std::cout << "Library: " << path << '\n'
                  << "  base: 0x" << std::hex << lib.base_addr << '\n'
                  << "  handle: 0x" << lib.handle << std::dec << '\n'
                  << "  original: " << lib.is_original << '\n'
                  << "  active: " << lib.is_active << '\n';

        if (!lib.patched_functions.empty()) {
            std::cout << "  patched functions:";
            for (const auto& f : lib.patched_functions)
                std::cout << ' ' << f;
            std::cout << '\n';
        }

        if (!lib.provided_functions.empty()) {
            std::cout << "  provides functions:";
            for (const auto& f : lib.provided_functions)
                std::cout << ' ' << f;
            std::cout << '\n';
        }

        if (!lib.patched_libraries.empty()) {
            std::cout << "  patches libraries:";
            for (const auto& l : lib.patched_libraries)
                std::cout << ' ' << l;
            std::cout << '\n';
        }

        if (!lib.saved_original_got.empty())
            std::cout << "  GOT backups: " << lib.saved_original_got.size() << '\n';
        if (!lib.saved_original_bytes.empty())
            std::cout << "  JMP backups: " << lib.saved_original_bytes.size() << '\n';
    }
}
