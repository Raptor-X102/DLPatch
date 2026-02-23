// frontend.hpp
#ifndef FRONTEND_HPP
#define FRONTEND_HPP

#include "DL_Manager.hpp"
#include <string>
#include <vector>
#include <map>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class Frontend {
public:
    explicit Frontend(pid_t pid);
    ~Frontend() = default;

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
    bool ensure_daemon_running() const;
    std::string get_state_path() const;
    bool save_state() const;
    bool load_state();
    static std::string bytes_to_hex(const std::vector<uint8_t> &bytes);
    static std::vector<uint8_t> hex_to_bytes(const std::string &hex);
    static std::string ptr_to_hex(uintptr_t ptr);
    static uintptr_t hex_to_ptr(const std::string &hex);

    pid_t pid_;
    DL_Manager mgr_;
    std::string state_path_;
};

#include "frontend.ipp"
#endif
