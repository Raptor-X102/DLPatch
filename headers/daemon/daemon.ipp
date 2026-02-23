// daemon.cpp
#include "daemon.hpp"
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

using json = nlohmann::json;

static std::string get_home_dir() {
    const char* home = getenv("HOME");
    if (home) return home;
    struct passwd* pw = getpwuid(getuid());
    return pw ? pw->pw_dir : ".";
}

static bool ensure_dir(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        return S_ISDIR(st.st_mode);
    }
    return mkdir(path.c_str(), 0700) == 0;
}

static std::string read_file(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    return std::string((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
}

static bool write_file(const std::string& path, const std::string& content) {
    std::ofstream f(path);
    if (!f.is_open()) return false;
    f << content;
    return f.good();
}

static unsigned long long get_process_starttime(pid_t pid) {
    std::string path = "/proc/" + std::to_string(pid) + "/stat";
    std::ifstream f(path);
    if (!f.is_open()) return 0;
    std::string line;
    std::getline(f, line);
    f.close();

    size_t pos = 0;
    int field = 0;
    while (field < 21 && pos < line.size()) {
        if (line[pos] == ' ') ++field;
        ++pos;
    }
    if (field == 21) {
        return std::stoull(line.substr(pos));
    }
    return 0;
}

Daemon::Daemon() : running_(false), interval_(5) {
    home_dir_ = get_home_dir();
    base_dir_ = home_dir_ + "/.dl_manager";
    ensure_dir(base_dir_);
    ensure_dir(get_state_dir());
}

Daemon::~Daemon() = default;

std::string Daemon::get_state_dir() const {
    return base_dir_ + "/state";
}

std::string Daemon::get_pid_file() const {
    return base_dir_ + "/daemon.pid";
}

bool Daemon::write_pid_file() const {
    return write_file(get_pid_file(), std::to_string(getpid()));
}

void Daemon::remove_pid_file() const {
    unlink(get_pid_file().c_str());
}

bool Daemon::is_running() {
    std::string pid_str = read_file(get_home_dir() + "/.dl_manager/daemon.pid");
    if (pid_str.empty()) return false;
    pid_t pid = std::stoi(pid_str);
    return kill(pid, 0) == 0;
}

bool Daemon::start() {
    if (is_running()) return true;

    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid > 0) return true;

    // First child
    if (setsid() < 0) _exit(1);
    pid = fork();
    if (pid < 0) _exit(1);
    if (pid > 0) _exit(0);

    // Daemon process
    umask(0);
    chdir("/");
    for (int fd = sysconf(_SC_OPEN_MAX); fd >= 0; --fd) close(fd);
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY);

    Daemon daemon;
    if (!daemon.write_pid_file()) _exit(1);
    daemon.run();
    daemon.remove_pid_file();
    _exit(0);
}

bool Daemon::stop_daemon() {
    std::string pid_str = read_file(get_home_dir() + "/.dl_manager/daemon.pid");
    if (pid_str.empty()) return false;
    pid_t pid = std::stoi(pid_str);
    return kill(pid, SIGTERM) == 0;
}

bool Daemon::status() {
    return is_running();
}

void Daemon::stop() {
    running_ = false;
}

void Daemon::run() {
    running_ = true;
    while (running_) {
        cleanup_dead_processes();
        std::this_thread::sleep_for(interval_);
    }
}

void Daemon::cleanup_dead_processes() {
    DIR* dir = opendir(get_state_dir().c_str());
    if (!dir) return;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_REG) continue;
        std::string name = entry->d_name;
        if (name.size() < 5 || name.substr(name.size()-5) != ".json") continue;

        std::string full_path = get_state_dir() + "/" + name;
        std::string content = read_file(full_path);
        if (content.empty()) {
            unlink(full_path.c_str());
            continue;
        }

        try {
            json j = json::parse(content);
            if (!j.contains("pid") || !j.contains("starttime")) {
                unlink(full_path.c_str());
                continue;
            }

            pid_t pid = j["pid"];
            unsigned long long saved_start = j["starttime"];
            unsigned long long now_start = get_process_starttime(pid);
            if (now_start == 0 || now_start != saved_start) {
                unlink(full_path.c_str());
            }
        } catch (...) {
            unlink(full_path.c_str());
        }
    }
    closedir(dir);
}
