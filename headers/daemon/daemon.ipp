//=============================================================================
// daemon.ipp
// Implementation of the cleanup daemon
//=============================================================================

using json = nlohmann::json;

static Daemon* g_daemon = nullptr;  // Global pointer for signal handler

//=============================================================================
// Internal helper functions
//=============================================================================

/**
 * @brief Get user's home directory (from HOME env or passwd)
 * @return Home directory path
 */
static std::string get_home_dir() {
    const char* home = getenv("HOME");
    if (home) return home;
    struct passwd* pw = getpwuid(getuid());
    return pw ? pw->pw_dir : ".";
}

/**
 * @brief Ensure directory exists, create if necessary
 * @param path Directory path
 * @return true if directory exists or was created successfully
 */
static bool ensure_dir(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        return S_ISDIR(st.st_mode);
    }
    return mkdir(path.c_str(), 0700) == 0;
}

/**
 * @brief Read entire file into string
 * @param path File path
 * @return File contents, empty string on error
 */
static std::string read_file(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    return std::string((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
}

/**
 * @brief Write string to file
 * @param path File path
 * @param content Content to write
 * @return true if write succeeded
 */
static bool write_file(const std::string& path, const std::string& content) {
    std::ofstream f(path);
    if (!f.is_open()) return false;
    f << content;
    return f.good();
}

/**
 * @brief Get process start time from /proc/[pid]/stat
 * @param pid Process ID
 * @return Start time in jiffies (field 21 in /proc/pid/stat)
 * 
 * Used to detect PID reuse - if start time differs, it's a different process
 * even though the PID is the same.
 */
static unsigned long long get_process_starttime(pid_t pid) {
    std::string path = "/proc/" + std::to_string(pid) + "/stat";
    std::ifstream f(path);
    if (!f.is_open()) return 0;
    std::string line;
    std::getline(f, line);
    f.close();

    // Skip to field 21 (starttime)
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

//=============================================================================
// Daemon implementation
//=============================================================================

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
    if (pid > 0) return true;  // Parent returns

    // First child - create new session
    if (setsid() < 0) _exit(1);
    
    pid = fork();
    if (pid < 0) _exit(1);
    if (pid > 0) _exit(0);  // First child exits, second child becomes daemon

    // Daemon process
    umask(0);
    chdir("/");
    
    // Close all file descriptors
    for (int fd = sysconf(_SC_OPEN_MAX); fd >= 0; --fd) close(fd);
    
    // Redirect stdin/stdout/stderr to /dev/null
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

void Daemon::setup_signal_handlers() {
    struct sigaction sa;
    sa.sa_handler = [](int) {
        if (g_daemon) g_daemon->stop();
    };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT, &sa, nullptr);
}

void Daemon::stop() {
    running_ = false;
}

void Daemon::run() {
    g_daemon = this;
    setup_signal_handlers();
    running_ = true;
    
    while (running_) {
        cleanup_dead_processes();
        std::this_thread::sleep_for(interval_);
    }
    
    g_daemon = nullptr;
}

void Daemon::cleanup_dead_processes() {
    DIR* dir = opendir(get_state_dir().c_str());
    if (!dir) return;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_REG) continue;  // Only regular files
        
        std::string name = entry->d_name;
        if (name.size() < 5 || name.substr(name.size() - 5) != ".json") continue;

        std::string full_path = get_state_dir() + "/" + name;
        std::string content = read_file(full_path);
        if (content.empty()) {
            unlink(full_path.c_str());
            continue;
        }

        try {
            json j = json::parse(content);
            if (!j.contains("pid")) {
                unlink(full_path.c_str());
                continue;
            }

            pid_t pid = j["pid"];
            
            // First check if process exists
            if (kill(pid, 0) != 0) {
                // Process is dead - safe to delete
                unlink(full_path.c_str());
                continue;
            }
            
            // Process exists - check if it's the same process instance
            if (j.contains("starttime")) {
                unsigned long long saved_start = j["starttime"];
                unsigned long long now_start = get_process_starttime(pid);
                
                // Only delete if starttime differs AND we could read it
                if (now_start != 0 && now_start != saved_start) {
                    // Different start time - process was reused, original is dead
                    unlink(full_path.c_str());
                }
                // Otherwise keep it - process is alive and is the same instance
            }
            // If no starttime in json, keep it - process is alive
        } catch (...) {
            // Invalid JSON - delete
            unlink(full_path.c_str());
        }
    }
    closedir(dir);
}
