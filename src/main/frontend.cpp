//=============================================================================
// frontend.cpp
// Command-line interface entry point for the DL Manager tool
//=============================================================================

#include "frontend.hpp"
#include <sys/capability.h>
#include <iostream>
#include <string>
#include <cstring>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>

/**
 * @brief Check if the process has CAP_SYS_PTRACE capability
 * 
 * Displays a warning if the capability is missing, as it's required
 * to trace processes not started by this tool.
 */
static void check_ptrace_capability() {
    cap_t caps = cap_get_proc();
    if (!caps) {
        std::cerr << "Warning: Could not check capabilities: " << strerror(errno)
                  << std::endl;
        return;
    }

    cap_flag_value_t cap_sys_ptrace;
    if (cap_get_flag(caps, CAP_SYS_PTRACE, CAP_EFFECTIVE, &cap_sys_ptrace) != 0) {
        std::cerr << "Warning: Could not get CAP_SYS_PTRACE flag: " << strerror(errno)
                  << std::endl;
        cap_free(caps);
        return;
    }

    if (!cap_sys_ptrace) {
        std::cerr
            << "\n[NOTE] The program lacks CAP_SYS_PTRACE capability.\n"
            << "       To replace libraries in processes not started by this tool,\n"
            << "       you need to add this capability:\n"
            << "         sudo setcap cap_sys_ptrace=eip ./build/dl_manager\n"
            << "         sudo setcap cap_sys_ptrace=eip ./build/dl_manager_daemon\n"
            << "       Or run with sudo (not recommended).\n\n";
    }

    cap_free(caps);
}

/**
 * @brief Print usage information
 * @param prog Program name
 */
static void print_usage(const char *prog) {
    std::cerr << "Usage:\n"
              << "  " << prog << " list <pid>\n"
              << "  " << prog << " symbols <pid> <library_pattern>\n"
              << "  " << prog << " replace <pid> <target_lib> <new_lib> [function]\n"
              << "  " << prog << " rollback <pid> <lib_path> [function]\n"
              << "  " << prog << " unload <pid> <lib_path>\n"
              << "  " << prog << " status <pid>\n";
}

/**
 * @brief Main entry point
 * @param argc Argument count
 * @param argv Argument vector
 * @return 0 on success, 1 on error
 * 
 * Parses command line arguments and dispatches to appropriate Frontend methods.
 */
int main(int argc, char **argv) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    std::string cmd = argv[1];
    pid_t pid = std::stoi(argv[2]);

    check_ptrace_capability();
    
    // Check if target process exists
    if (kill(pid, 0) != 0) {
        std::cerr << "Process " << pid << " does not exist.\n";
        return 1;
    }

    Frontend frontend(pid);

    if (cmd == "list") {
        return frontend.list_libraries() ? 0 : 1;
    }

    if (cmd == "symbols") {
        if (argc < 4) {
            print_usage(argv[0]);
            return 1;
        }
        return frontend.list_symbols(argv[3]) ? 0 : 1;
    }

    if (cmd == "replace") {
        if (argc < 5) {
            print_usage(argv[0]);
            return 1;
        }
        std::string target = argv[3];
        std::string new_lib = argv[4];
        std::string func = (argc >= 6) ? argv[5] : "all";
        return frontend.replace_library(target, new_lib, func) ? 0 : 1;
    }

    if (cmd == "rollback") {
        if (argc < 4) {
            print_usage(argv[0]);
            return 1;
        }
        std::string lib = argv[3];
        if (argc >= 5) {
            return frontend.rollback_function(lib, argv[4]) ? 0 : 1;
        } else {
            return frontend.rollback_library(lib) ? 0 : 1;
        }
    }

    if (cmd == "unload") {
        if (argc < 4) {
            print_usage(argv[0]);
            return 1;
        }
        return frontend.unload_library(argv[3]) ? 0 : 1;
    }

    if (cmd == "status") {
        frontend.print_status();
        return 0;
    }

    print_usage(argv[0]);
    return 1;
}
