//=============================================================================
// daemon.hpp
// Header for the cleanup daemon that manages orphaned state files
//=============================================================================

#ifndef DAEMON_HPP
#define DAEMON_HPP

#include <string>
#include <atomic>
#include <chrono>
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <thread>
#include <cstring>
#include <nlohmann/json.hpp>

/**
 * @brief Background daemon that cleans up state files of terminated processes
 * 
 * The daemon runs in the background and periodically scans the state directory
 * (~/.dl_manager/state/) for JSON files belonging to processes that no longer
 * exist. It uses process start times to ensure it doesn't delete files of
 * processes that have been replaced by new instances with the same PID.
 */
class Daemon {
public:
    Daemon();
    ~Daemon();

    //=========================================================================
    // Main control methods
    //=========================================================================

    /**
     * @brief Run the main monitoring loop (blocks)
     * 
     * This is the main daemon loop that runs in the background process.
     * It periodically calls cleanup_dead_processes().
     */
    void run();

    /**
     * @brief Stop the loop (called from signal handler)
     * 
     * Sets running_ flag to false, causing the main loop to exit.
     */
    void stop();

    //=========================================================================
    // Static control methods (for frontend)
    //=========================================================================

    /**
     * @brief Check if daemon is already running via pid file
     * @return true if daemon process exists and responds to signals
     */
    static bool is_running();

    /**
     * @brief Start the daemon (fork, detach, etc.)
     * @return true if daemon started successfully or already running
     * 
     * Forks twice to detach from terminal, closes all file descriptors,
     * and runs the daemon in the background.
     */
    static bool start();

    /**
     * @brief Stop the daemon by sending SIGTERM to the process in pid file
     * @return true if signal was sent successfully
     */
    static bool stop_daemon();

    /**
     * @brief Check daemon status
     * @return true if daemon is running (same as is_running())
     */
    static bool status();

private:
    //=========================================================================
    // Internal methods
    //=========================================================================

    /**
     * @brief Main monitoring logic - scans and cleans up dead process state files
     * 
     * For each .json file in the state directory:
     * 1. Reads and parses the JSON
     * 2. Checks if the process exists (kill(pid, 0))
     * 3. If process exists, compares saved start time with current start time
     * 4. Deletes file if process is dead or start time changed (PID reused)
     */
    void cleanup_dead_processes();

    /**
     * @brief Get the state directory path (~/.dl_manager/state/)
     * @return Path to state directory
     */
    std::string get_state_dir() const;

    /**
     * @brief Get the pid file path (~/.dl_manager/daemon.pid)
     * @return Path to pid file
     */
    std::string get_pid_file() const;

    /**
     * @brief Write current process ID to pid file
     * @return true if write succeeded
     */
    bool write_pid_file() const;

    /**
     * @brief Remove the pid file (on daemon exit)
     */
    void remove_pid_file() const;

    /**
     * @brief Set up signal handlers for graceful shutdown
     * 
     * Handles SIGTERM and SIGINT to stop the daemon cleanly.
     */
    void setup_signal_handlers();

    //=========================================================================
    // Member variables
    //=========================================================================

    std::atomic<bool> running_;          // Control flag for main loop
    std::chrono::seconds interval_;      // Sleep interval between scans
    std::string home_dir_;                // User's home directory
    std::string base_dir_;                // Base directory (~/.dl_manager)
};

// Include implementation
#include "daemon.ipp"

#endif // DAEMON_HPP
