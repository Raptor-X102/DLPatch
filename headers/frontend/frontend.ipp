// frontend.cpp
#include "frontend.hpp"
#include "daemon.hpp"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <unistd.h>
#include <sys/wait.h>

Frontend::Frontend(pid_t pid) : pid_(pid), mgr_(pid) {
    state_path_ = get_state_path();
    load_state();
}

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
    
    if (mkdir(base_dir.c_str(), 0700) != 0 && errno != EEXIST) {
        LOG_ERR("Failed to create directory %s: %s", base_dir.c_str(), strerror(errno));
    }
    if (mkdir(state_dir.c_str(), 0700) != 0 && errno != EEXIST) {
        LOG_ERR("Failed to create directory %s: %s", state_dir.c_str(), strerror(errno));
    }
    
    return state_dir + "/" + std::to_string(pid_) + ".json";
}

std::string Frontend::ptr_to_hex(uintptr_t ptr) {
    std::stringstream ss;
    ss << "0x" << std::hex << ptr;
    return ss.str();
}

uintptr_t Frontend::hex_to_ptr(const std::string& hex) {
    if (hex.size() > 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
        return std::stoull(hex.substr(2), nullptr, 16);
    return std::stoull(hex, nullptr, 16);
}

std::string Frontend::bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : bytes)
        ss << std::setw(2) << (int)b;
    return ss.str();
}

std::vector<uint8_t> Frontend::hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
        bytes.push_back(std::stoi(hex.substr(i, 2), nullptr, 16));
    return bytes;
}

bool Frontend::load_state() {
    std::ifstream f(state_path_);
    if (!f.is_open()) return false;

    json j;
    try {
        f >> j;
        if (!j.contains("pid") || j["pid"] != pid_) return false;

        auto libs = mgr_.get_tracked_libraries();
        libs.clear();

        for (const auto& item : j["tracked_libraries"]) {
            TrackedLibrary lib;
            lib.path = item.value("path", "");
            lib.handle = hex_to_ptr(item.value("handle", "0"));
            lib.base_addr = hex_to_ptr(item.value("base_addr", "0"));
            lib.is_original = item.value("is_original", false);
            lib.is_active = item.value("is_active", false);

            if (item.contains("patched_functions"))
                lib.patched_functions = item["patched_functions"].get<std::vector<std::string>>();
            if (item.contains("provided_functions"))
                lib.provided_functions = item["provided_functions"].get<std::vector<std::string>>();
            if (item.contains("patched_libraries"))
                lib.patched_libraries = item["patched_libraries"].get<std::vector<std::string>>();

            if (item.contains("saved_original_got")) {
                for (auto& [key, val] : item["saved_original_got"].items())
                    lib.saved_original_got[key] = hex_to_ptr(val);
            }
            if (item.contains("saved_original_bytes")) {
                for (auto& [key, val] : item["saved_original_bytes"].items())
                    lib.saved_original_bytes[key] = hex_to_bytes(val);
            }

            libs[lib.path] = lib;
        }
        mgr_.set_tracked_libraries(libs);
        return true;
    } catch (...) {
        return false;
    }
}

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
    for (const auto& [_, lib] : libs) {
        json item;
        item["path"] = lib.path;
        item["handle"] = ptr_to_hex(lib.handle);
        item["base_addr"] = ptr_to_hex(lib.base_addr);
        item["is_original"] = lib.is_original;
        item["is_active"] = lib.is_active;
        item["patched_functions"] = lib.patched_functions;
        item["provided_functions"] = lib.provided_functions;
        item["patched_libraries"] = lib.patched_libraries;

        json got;
        for (const auto& [f, a] : lib.saved_original_got)
            got[f] = ptr_to_hex(a);
        item["saved_original_got"] = got;

        json bytes;
        for (const auto& [f, v] : lib.saved_original_bytes)
            bytes[f] = bytes_to_hex(v);
        item["saved_original_bytes"] = bytes;

        j["tracked_libraries"].push_back(item);
    }

    f << j.dump(4);
    if (!f.good()) {
        LOG_ERR("Failed to write state file");
        return false;
    }
    
    LOG_INFO("State saved to %s", path.c_str());
    return true;
}

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

bool Frontend::list_libraries() const {
    auto libs = mgr_.get_loaded_libraries();
    if (libs.empty()) {
        std::cout << "No libraries found.\n";
        return true;
    }
    for (const auto& lib : libs)
        std::cout << lib << '\n';
    return true;
}

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

bool Frontend::replace_library(const std::string& target, const std::string& new_lib, const std::string& func) {
    bool ok = mgr_.replace_library(target, new_lib, func);
    if (ok) {
        save_state();
        ensure_daemon_running();
    }
    return ok;
}

// headers/frontend/frontend.ipp - исправление с отладкой
bool Frontend::rollback_library(const std::string& lib) {
    auto tracked = mgr_.get_tracked_libraries();
    
    // Debug: показать все сохранённые пути
    std::cerr << "Tracked libraries:" << std::endl;
    for (const auto& [path, _] : tracked) {
        std::cerr << "  " << path << std::endl;
    }
    
    std::string found_path;
    std::string lib_basename = lib.substr(lib.find_last_of('/') + 1);
    
    for (const auto& [path, _] : tracked) {
        // Сравниваем по базовому имени файла
        std::string path_basename = path.substr(path.find_last_of('/') + 1);
        if (path_basename == lib_basename) {
            found_path = path;
            break;
        }
    }
    
    if (found_path.empty()) {
        std::cerr << "Library not found in tracker: " << lib << std::endl;
        return false;
    }
    
    std::cerr << "Found matching library: " << found_path << std::endl;
    bool ok = mgr_.rollback_library(found_path);
    if (ok) save_state();
    return ok;
}

bool Frontend::rollback_function(const std::string& lib, const std::string& func) {
    auto tracked = mgr_.get_tracked_libraries();
    
    std::cerr << "Tracked libraries:" << std::endl;
    for (const auto& [path, _] : tracked) {
        std::cerr << "  " << path << std::endl;
    }
    
    std::string found_path;
    std::string lib_basename = lib.substr(lib.find_last_of('/') + 1);
    
    for (const auto& [path, _] : tracked) {
        std::string path_basename = path.substr(path.find_last_of('/') + 1);
        if (path_basename == lib_basename) {
            found_path = path;
            break;
        }
    }
    
    if (found_path.empty()) {
        std::cerr << "Library not found in tracker: " << lib << std::endl;
        return false;
    }
    
    std::cerr << "Found matching library: " << found_path << std::endl;
    bool ok = mgr_.rollback_function(found_path, func);
    if (ok) save_state();
    return ok;
}

bool Frontend::unload_library(const std::string& lib) {
    bool ok = mgr_.unload_library(lib);
    if (ok) save_state();
    return ok;
}

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
