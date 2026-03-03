//=============================================================================
// daemon.cpp
// Entry point for the daemon executable
//=============================================================================

#include "daemon.hpp"
#include <iostream>
#include <csignal>

/**
 * @brief Daemon main entry point
 * @param argc Argument count
 * @param argv Argument vector
 * @return 0 on success, 1 on error
 * 
 * Usage: dlpatchd {start|stop|status}
 *   start  - Start the background daemon
 *   stop   - Stop the running daemon
 *   status - Check if daemon is running
 */
int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " {start|stop|status}\n";
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "start") {
        if (Daemon::is_running()) {
            std::cout << "Daemon already running.\n";
            return 0;
        }
        if (!Daemon::start()) {
            std::cerr << "Failed to start daemon.\n";
            return 1;
        }
        std::cout << "Daemon started.\n";
        return 0;
    } else if (cmd == "stop") {
        if (!Daemon::stop_daemon()) {
            std::cerr << "Failed to stop daemon (maybe not running).\n";
            return 1;
        }
        std::cout << "Daemon stop signal sent.\n";
        return 0;
    } else if (cmd == "status") {
        std::cout << (Daemon::status() ? "running" : "not running") << "\n";
        return 0;
    } else {
        std::cerr << "Unknown command.\n";
        return 1;
    }
}
