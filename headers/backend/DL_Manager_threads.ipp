static std::vector<pid_t> get_all_threads(pid_t pid) {
    std::vector<pid_t> tids;
    std::string task_path = "/proc/" + std::to_string(pid) + "/task/";

    DIR* dir = opendir(task_path.c_str());
    if (!dir) return tids;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type == DT_DIR) {
            bool is_number = true;
            for (char* p = entry->d_name; *p; ++p) {
                if (!isdigit(*p)) { is_number = false; break; }
            }
            if (is_number) tids.push_back(atoi(entry->d_name));
        }
    }
    closedir(dir);

    std::sort(tids.begin(), tids.end());
    return tids;
}

static bool stop_all_threads(const std::vector<pid_t>& tids, std::vector<ThreadContext>& contexts) {
    contexts.clear();
    for (pid_t tid : tids) {
        if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == -1) {
            LOG_ERR("ptrace ATTACH failed for thread %d", tid);
            for (const auto& ctx : contexts) {
                ptrace(PTRACE_DETACH, ctx.tid, nullptr, nullptr);
            }
            return false;
        }
        int status;
        waitpid(tid, &status, 0);
        if (!WIFSTOPPED(status)) {
            LOG_ERR("Thread %d did not stop after attach", tid);
            for (const auto& ctx : contexts) {
                ptrace(PTRACE_DETACH, ctx.tid, nullptr, nullptr);
            }
            return false;
        }
        ThreadContext ctx;
        ctx.tid = tid;
        if (ptrace(PTRACE_GETREGS, tid, nullptr, &ctx.regs) == -1) {
            LOG_ERR("ptrace GETREGS failed for thread %d", tid);
            ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
            for (const auto& c : contexts) {
                ptrace(PTRACE_DETACH, c.tid, nullptr, nullptr);
            }
            return false;
        }
        contexts.push_back(ctx);
    }
    return true;
}

static bool all_threads_outside(const std::vector<ThreadContext>& contexts,
                                const std::vector<std::pair<uintptr_t, uintptr_t>>& segments) {
    for (const auto& ctx : contexts) {
        if (address_in_library(Arch::get_ip(ctx.regs), segments)) {
            return false;
        }
    }
    return true;
}

static void restore_and_detach_all(const std::vector<ThreadContext>& contexts) {
    for (const auto& ctx : contexts) {
        ptrace(PTRACE_SETREGS, ctx.tid, nullptr, &ctx.regs);
        ptrace(PTRACE_DETACH, ctx.tid, nullptr, nullptr);
    }
}

static long ptrace_read(pid_t tid, uintptr_t addr) {
    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA, tid, addr, nullptr);
    if (data == -1 && errno != 0) return -1;
    return data;
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

bool DL_Manager::prepare_thread_for_injection(pid_t tid, struct user_regs_struct& prepared_regs) {
    LOG_DBG("Preparing thread %d for injection", tid);

    // Execute two PTRACE_SYSCALL steps to ensure thread is out of any syscall
    // Reason: If thread is inside a syscall when we try to execute shellcode,
    // the kernel will restart the syscall after we detach, corrupting program state
    // First PTRACE_SYSCALL: 
    //   - If thread was in syscall, it will exit it and stop on syscall exit
    //   - If thread was not in syscall, it will enter next syscall and stop on entry
    // Second PTRACE_SYSCALL:
    //   - Ensures thread is stopped at a safe point (not inside any syscall)
    for (int i = 0; i < 2; ++i) {
        if (ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr) == -1) {
            LOG_ERR("ptrace SYSCALL failed during preparation (attempt %d)", i);
            return false;
        }
        
        int status;
        waitpid(tid, &status, 0);
        
        if (!WIFSTOPPED(status)) {
            LOG_ERR("Thread did not stop after PTRACE_SYSCALL (attempt %d)", i);
            return false;
        }
        
        int sig = WSTOPSIG(status);
        if (sig != SIGTRAP) {
            LOG_DBG("Thread stopped with signal %d (expected SIGTRAP)", sig);
        }
    }
    
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &prepared_regs) == -1) {
        LOG_ERR("Failed to get registers after preparation");
        return false;
    }
    
    LOG_DBG("Thread prepared: IP=0x%llx, SP=0x%llx", 
            (unsigned long long)Arch::get_ip(prepared_regs),
            (unsigned long long)Arch::get_sp(prepared_regs));
    
    return true;
}

bool DL_Manager::wait_for_threads_to_leave_library(const std::vector<pid_t>& all_tids,
                                                    const std::vector<std::pair<uintptr_t, uintptr_t>>& segments,
                                                    std::vector<pid_t>& stopped_tids,
                                                    int max_attempts, int retry_us) {
    stopped_tids.clear();
    std::set<pid_t> remaining(all_tids.begin(), all_tids.end());
    std::map<pid_t, bool> inside;

    for (int attempt = 0; attempt < max_attempts && !remaining.empty(); ++attempt) {
        auto it = remaining.begin();
        while (it != remaining.end()) {
            pid_t tid = *it;

            if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == -1) {
                if (errno == ESRCH) {
                    LOG_WARN("Thread %d no longer exists, removing from list", tid);
                    it = remaining.erase(it);
                    continue;
                }
                LOG_ERR("ptrace ATTACH failed for thread %d, errno=%d", tid, errno);
                ++it;
                continue;
            }

            int status;
            waitpid(tid, &status, 0);
            if (!WIFSTOPPED(status)) {
                LOG_WARN("Thread %d did not stop after attach", tid);
                ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
                ++it;
                continue;
            }

            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) == -1) {
                LOG_ERR("ptrace GETREGS failed for thread %d", tid);
                ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
                ++it;
                continue;
            }

            bool in_lib = address_in_library(Arch::get_ip(regs), segments);
            if (in_lib) {
                LOG_DBG("Thread %d is inside library (IP=0x%lx), detaching and will retry", tid, Arch::get_ip(regs));
                ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
                inside[tid] = true;
                ++it;
            } else {
                LOG_DBG("Thread %d is outside library, stopping permanently", tid);
                stopped_tids.push_back(tid);
                it = remaining.erase(it);
                inside.erase(tid);
            }
        }

        if (!remaining.empty()) {
            LOG_INFO("Still waiting for %zu threads to leave library, attempt %d/%d",
                     remaining.size(), attempt + 1, max_attempts);
            usleep(retry_us);
        }
    }

    if (!remaining.empty()) {
        LOG_ERR("Timeout: %zu threads still inside library after %d attempts", remaining.size(), max_attempts);
        for (pid_t tid : stopped_tids) {
            ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
        }
        stopped_tids.clear();
        return false;
    }

    LOG_INFO("All threads are now outside the library, %zu threads stopped", stopped_tids.size());
    return true;
}

bool DL_Manager::freeze_threads_outside_library(const std::vector<pid_t>& all_tids,
                                                 const std::vector<std::pair<uintptr_t, uintptr_t>>& segments,
                                                 std::vector<ThreadContext>& contexts) {
    const int MAX_ATTEMPTS = 50;
    const int RETRY_US = 10000;

    for (int attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
        if (!stop_all_threads(all_tids, contexts)) {
            LOG_ERR("Failed to stop threads on attempt %d", attempt + 1);
            return false;
        }

        // Check if all threads are outside the library
        if (all_threads_outside(contexts, segments)) {
            return true;
        }

        // Still inside - detach and retry
        restore_and_detach_all(contexts);
        contexts.clear();
        usleep(RETRY_US);
    }

    LOG_ERR("Failed to freeze all threads outside the library after %d attempts", MAX_ATTEMPTS);
    return false;
}

void DL_Manager::select_worker_thread(const std::vector<ThreadContext>& contexts, pid_t& worker_tid) {
    // Prefer main thread (pid_)
    for (const auto& ctx : contexts) {
        if (ctx.tid == pid_) {
            worker_tid = ctx.tid;
            return;
        }
    }
    
    // Fallback to first available thread
    worker_tid = contexts[0].tid;
    LOG_INFO("Main thread not found, using thread %d for injection", worker_tid);
}
