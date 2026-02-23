// main_daemon.cpp
#include "daemon.hpp"
#include <iostream>
#include <csignal>

static Daemon* g_daemon = nullptr;

void signal_handler(int) {
    if (g_daemon) g_daemon->stop();
}

int main(int argc, char** argv) {
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
