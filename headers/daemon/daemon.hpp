// daemon.hpp
#ifndef DAEMON_HPP
#define DAEMON_HPP

#include <string>
#include <atomic>
#include <chrono>

class Daemon {
public:
    Daemon();
    ~Daemon();

    // Run the main monitoring loop (blocks)
    void run();

    // Stop the loop (called from signal handler)
    void stop();

    // Check if daemon is already running via pid file
    static bool is_running();

    // Start the daemon (fork, detach, etc.)
    static bool start();

    // Stop the daemon by sending SIGTERM to the process in pid file
    static bool stop_daemon();

    // Return true if daemon is running
    static bool status();

private:
    void monitor_loop();
    void cleanup_dead_processes();
    std::string get_state_dir() const;
    std::string get_pid_file() const;
    bool write_pid_file() const;
    void remove_pid_file() const;

    std::atomic<bool> running_;
    std::chrono::seconds interval_;
    std::string home_dir_;
    std::string base_dir_;
};

#include "daemon.ipp"

#endif // DAEMON_HPP
