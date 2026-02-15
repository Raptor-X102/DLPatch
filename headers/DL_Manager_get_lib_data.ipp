#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <cctype>

std::vector<std::string> DL_Manager::get_loaded_libraries() const {
    std::vector<std::string> libs;
    std::string maps_path = "/proc/" + std::to_string(pid_) + "/maps";
    std::ifstream file(maps_path);

    if (!file.is_open()) {
        std::cerr << "Error: cannot open " << maps_path << std::endl;
        return libs;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.find(".so") == std::string::npos) {
            continue;
        }

        std::istringstream iss(line);
        std::string address, perms, offset, dev, inode;
        std::string pathname;

        iss >> address >> perms >> offset >> dev >> inode;
        std::getline(iss, pathname);

        if (!pathname.empty() && pathname[0] == ' ') {
            pathname = pathname.substr(1);
        }

        if (!pathname.empty()) {
            libs.push_back(pathname);
        }
    }

    std::sort(libs.begin(), libs.end());
    libs.erase(std::unique(libs.begin(), libs.end()), libs.end());
    return libs;
}

void DL_Manager::print_loaded_libraries() const {
    auto libs = get_loaded_libraries();
    std::cout << "Loaded libraries in PID " << pid_ << ":\n";
    if (libs.empty()) {
        std::cout << "  No libraries found.\n";
    } else {
        for (const auto& lib : libs) {
            std::cout << "  " << lib << std::endl;
        }
    }
}

LibraryInfo DL_Manager::get_library_info(const std::string& lib_name) const {
    LibraryInfo info;
    info.base_addr = 0;
    info.size = 0;
    std::string maps_path = "/proc/" + std::to_string(pid_) + "/maps";
    std::ifstream file(maps_path);

    if (!file.is_open()) {
        std::cerr << "Error: cannot open " << maps_path << std::endl;
        return info;
    }

    std::string line;
    uintptr_t min_addr = ~0ULL;
    uintptr_t max_addr = 0;

    while (std::getline(file, line)) {
        if (line.find(lib_name) == std::string::npos) {
            continue;
        }

        std::istringstream iss(line);
        std::string addr_range, perms, offset, dev, inode, path;
        iss >> addr_range >> perms >> offset >> dev >> inode;
        std::getline(iss, path);

        if (!path.empty() && path[0] == ' ') {
            path = path.substr(1);
        }
        if (info.path.empty() && !path.empty()) {
            info.path = path;
        }

        size_t dash = addr_range.find('-');
        if (dash != std::string::npos) {
            uintptr_t start = std::stoul(addr_range.substr(0, dash), nullptr, 16);
            uintptr_t end = std::stoul(addr_range.substr(dash + 1), nullptr, 16);
            info.segments.emplace_back(start, end);

            if (start < min_addr) min_addr = start;
            if (end > max_addr) max_addr = end;
        }
    }

    if (min_addr != ~0ULL) {
        info.base_addr = min_addr;
        info.size = max_addr - min_addr;
    }

    return info;
}
