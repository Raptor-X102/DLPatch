//=============================================================================
// frontend.hpp
// Header for the Frontend class - user interface to DL_Manager
//=============================================================================

#ifndef FRONTEND_HPP
#define FRONTEND_HPP

#include "DL_Manager.hpp"
#include <string>
#include <vector>
#include <map>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

/**
 * @brief Frontend class providing command-line interface to DL_Manager
 * 
 * Handles:
 * - Command parsing and dispatch
 * - State persistence (save/load to JSON)
 * - User output formatting
 * - Daemon management
 */
class Frontend {
public:
    explicit Frontend(pid_t pid);
    ~Frontend() = default;

    //=========================================================================
    // Public command interface (called from main)
    //=========================================================================

    bool list_libraries() const;
    bool list_symbols(const std::string &pattern) const;
    bool replace_library(const std::string &target,
                         const std::string &new_lib,
                         const std::string &func);
    bool rollback_library(const std::string &lib);
    bool rollback_function(const std::string &lib, const std::string &func);
    bool unload_library(const std::string &lib);
    void print_status() const;

private:
    //=========================================================================
    // Daemon management
    //=========================================================================

    bool ensure_daemon_running() const;

    //=========================================================================
    // State persistence
    //=========================================================================

    std::string get_state_path() const;
    bool save_state() const;
    bool load_state();

    //=========================================================================
    // Conversion utilities for JSON serialization
    //=========================================================================

    static std::string bytes_to_hex(const std::vector<uint8_t> &bytes);
    static std::vector<uint8_t> hex_to_bytes(const std::string &hex);
    static std::string ptr_to_hex(uintptr_t ptr);
    static uintptr_t hex_to_ptr(const std::string &hex);

    //=========================================================================
    // Member variables
    //=========================================================================

    pid_t pid_;                     // Target process PID
    mutable DL_Manager mgr_;         // Core manager instance
    std::string state_path_;         // Path to state file for this PID
};

#include "frontend.ipp"
#endif // FRONTEND_HPP
