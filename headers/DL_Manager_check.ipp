// DL_Manager_check.ipp
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <dirent.h>
#include <cstring>
#include <vector>
#include <iostream>
#include <cctype>
#include <fstream>
#include <sstream>
#include <algorithm>

struct StackInfo {
    uintptr_t start;
    uintptr_t end;
    size_t size;
};

static StackInfo get_thread_stack_info(pid_t tid) {
    StackInfo info = {0, 0, 0};
    std::string maps_path = "/proc/" + std::to_string(tid) + "/maps";
    std::ifstream file(maps_path);
    
    if (!file.is_open()) {
        return info;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.find("[stack]") != std::string::npos) {
            size_t dash = line.find('-');
            if (dash != std::string::npos) {
                info.start = std::stoul(line.substr(0, dash), nullptr, 16);
                info.end = std::stoul(line.substr(dash + 1), nullptr, 16);
                info.size = info.end - info.start;
                break;
            }
        }
        if (line.find("rw-p") != std::string::npos && line.find("00:00") != std::string::npos) {
            size_t dash = line.find('-');
            if (dash != std::string::npos) {
                size_t space = line.find(' ', dash);
                if (space != std::string::npos) {
                    uintptr_t start = std::stoul(line.substr(0, dash), nullptr, 16);
                    uintptr_t end = std::stoul(line.substr(dash + 1, space - dash - 1), nullptr, 16);
                    size_t size = end - start;
                    if (size >= 1024 * 1024 && size <= 16 * 1024 * 1024) {
                        info.start = start;
                        info.end = end;
                        info.size = size;
                        break;
                    }
                }
            }
        }
    }
    return info;
}

static std::vector<pid_t> get_threads(pid_t pid) {
    std::vector<pid_t> tids;
    std::string task_path = "/proc/" + std::to_string(pid) + "/task/";
    
    DIR* dir = opendir(task_path.c_str());
    if (!dir) return tids;
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type == DT_DIR && isdigit(entry->d_name[0])) {
            tids.push_back(atoi(entry->d_name));
        }
    }
    closedir(dir);
    
    std::sort(tids.begin(), tids.end());
    return tids;
}

static long ptrace_read(pid_t tid, uintptr_t addr) {
    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA, tid, addr, nullptr);
    if (data == -1 && errno != 0) return -1;
    return data;
}

// Helper functions
static bool address_in_library(uintptr_t addr, const std::vector<std::pair<uintptr_t, uintptr_t>>& segments) {
    for (const auto& seg : segments) {
        if (addr >= seg.first && addr < seg.second) return true;
    }
    return false;
}

static bool stack_contains_library(pid_t tid, uintptr_t rsp,
                                   const std::vector<std::pair<uintptr_t, uintptr_t>>& segments) {
    StackInfo stack = get_thread_stack_info(tid);
    
    if (stack.start == 0 || stack.end == 0) {
        uintptr_t scan_limit = rsp + (64 * 1024);
        for (uintptr_t addr = rsp; addr < scan_limit; addr += sizeof(uintptr_t)) {
            long value = ptrace_read(tid, addr);
            if (value == -1 && errno != 0) break;
            if (address_in_library(static_cast<uintptr_t>(value), segments)) return true;
        }
        return false;
    }
    
    for (uintptr_t addr = rsp; addr < stack.end; addr += sizeof(uintptr_t)) {
        long value = ptrace_read(tid, addr);
        if (value == -1 && errno != 0) break;
        if (address_in_library(static_cast<uintptr_t>(value), segments)) return true;
    }
    return false;
}

static bool thread_uses_library(pid_t tid, const std::vector<std::pair<uintptr_t, uintptr_t>>& segments) {
    if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == -1) {
        LOG_ERR("ptrace ATTACH failed for thread %d", tid);
        return true;
    }
    
    int status;
    waitpid(tid, &status, 0);
    if (!WIFSTOPPED(status)) {
        LOG_WARN("Thread %d did not stop", tid);
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
        return true;
    }
    
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) == -1) {
        LOG_ERR("ptrace GETREGS failed for thread %d", tid);
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
        return true;
    }
    
    bool uses = false;
    if (address_in_library(regs.rip, segments)) uses = true;
    if (!uses && stack_contains_library(tid, regs.rsp, segments)) uses = true;
    
    ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
    return uses;
}

bool DL_Manager::is_safe_to_replace(const std::string& lib_name) const {
    LibraryInfo info = get_library_info(lib_name);
    if (info.segments.empty()) {
        LOG_ERR("Library '%s' not found in process %d", lib_name.c_str(), pid_);
        return false;
    }
    
    std::vector<pid_t> tids = get_threads(pid_);
    if (tids.empty()) {
        LOG_ERR("No threads found for PID %d", pid_);
        return false;
    }
    
    for (pid_t tid : tids) {
        if (thread_uses_library(tid, info.segments)) {
            LOG_WARN("Thread %d is currently using the library", tid);
            return false;
        }
    }
    return true;
}
