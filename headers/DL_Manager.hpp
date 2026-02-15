#ifndef LIBRARY_SCANNER_HPP
#define LIBRARY_SCANNER_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <sys/types.h>

struct LibraryInfo {
    std::string path;
    uintptr_t base_addr;
    size_t size;
    std::vector<std::pair<uintptr_t, uintptr_t>> segments;
};

class DL_Manager {
public:
    explicit DL_Manager(pid_t pid) : pid_(pid) {};

    std::vector<std::string> get_loaded_libraries() const;
    LibraryInfo get_library_info(const std::string& lib_name) const;
    bool is_safe_to_replace(const std::string& lib_name) const;
    void print_loaded_libraries() const;

    // New method: get address of a symbol in a loaded library using its base address
    uintptr_t get_symbol_address(uintptr_t lib_base, const std::string& sym_name) const;

    bool replace_library(const std::string& target_lib_pattern, const std::string& new_lib_path);
private:
    pid_t pid_;
};

// Include implementation files
#include "DL_Manager_get_lib_data.ipp"
#include "DL_Manager_check.ipp"
#include "DL_Manager_extract_funcs_from_lib.ipp"
#include "DL_manager_replace.ipp"

#endif // LIBRARY_SCANNER_HPP
