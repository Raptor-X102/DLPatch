//=============================================================================
// DL_Manager_threads.ipp
// Thread management and ptrace operations for target process
//=============================================================================

/**
 * @brief Get all thread IDs of the target process
 * @param pid Target process PID
 * @return Vector of thread IDs, sorted
 * 
 * Reads /proc/[pid]/task/ directory to enumerate all threads.
 */
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

/**
 * @brief Stop all specified threads and save their register contexts
 * @param tids Vector of thread IDs to stop
 * @param contexts [out] Vector of ThreadContext with saved registers
 * @return true if all threads stopped successfully, false otherwise
 * 
 * Attaches to each thread via ptrace, waits for it to stop, and saves its registers.
 * On failure, detaches all already-stopped threads.
 */
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

/**
 * @brief Check if all stopped threads are outside the specified library segments
 * @param contexts Vector of stopped thread contexts
 * @param segments Library memory segments to check against
 * @return true if all threads are outside, false if any thread is inside
 */
static bool all_threads_outside(const std::vector<ThreadContext>& contexts,
                                const std::vector<std::pair<uintptr_t, uintptr_t>>& segments) {
    for (const auto& ctx : contexts) {
        if (address_in_library(Arch::get_ip(ctx.regs), segments)) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Restore registers and detach all stopped threads
 * @param contexts Vector of thread contexts with saved registers
 * 
 * Restores original register values and detaches from each thread.
 * This is the proper cleanup after thread freezing.
 */
static void restore_and_detach_all(const std::vector<ThreadContext>& contexts) {
    for (const auto& ctx : contexts) {
        ptrace(PTRACE_SETREGS, ctx.tid, nullptr, &ctx.regs);
        ptrace(PTRACE_DETACH, ctx.tid, nullptr, nullptr);
    }
}

/**
 * @brief Read a word from remote process memory using ptrace
 * @param tid Thread ID
 * @param addr Address to read from
 * @return Data read, or -1 on error (check errno)
 * 
 * Wrapper around ptrace PEEKDATA for reading single words.
 */
static long ptrace_read(pid_t tid, uintptr_t addr) {
    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA, tid, addr, nullptr);
    if (data == -1 && errno != 0) return -1;
    return data;
}

/**
 * @brief Get thread IDs (simplified version, used by is_safe_to_replace)
 * @param pid Target process PID
 * @return Vector of thread IDs
 */
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

/**
 * @brief Get stack information for a thread from /proc/[tid]/maps
 * @param tid Thread ID
 * @return StackInfo structure with start, end, and size
 */
static StackInfo get_thread_stack_info(pid_t tid) {
    StackInfo info;
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
        // Fallback: look for anonymous RW mapping that might be stack
        if (line.find("rw-p") != std::string::npos && line.find("00:00") != std::string::npos) {
            size_t dash = line.find('-');
            if (dash != std::string::npos) {
                size_t space = line.find(' ', dash);
                if (space != std::string::npos) {
                    uintptr_t start = std::stoul(line.substr(0, dash), nullptr, 16);
                    uintptr_t end = std::stoul(line.substr(dash + 1, space - dash - 1), nullptr, 16);
                    size_t size = end - start;
                    // Stack is typically 1-16MB
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

/**
 * @brief Check if thread's stack contains pointers to library segments
 * @param tid Thread ID
 * @param rsp Current stack pointer
 * @param segments Library memory segments
 * @return true if any value on stack points into library
 * 
 * Scans thread's stack for pointers to the specified library segments.
 * Used to determine if thread might execute library code after returning.
 */
static bool stack_contains_library(pid_t tid, uintptr_t rsp,
                                   const std::vector<std::pair<uintptr_t, uintptr_t>>& segments) {
    StackInfo stack = get_thread_stack_info(tid);
    
    if (stack.start == 0 || stack.end == 0) {
        // Can't determine stack bounds, scan a reasonable portion
        uintptr_t scan_limit = rsp + (64 * 1024);
        for (uintptr_t addr = rsp; addr < scan_limit; addr += sizeof(uintptr_t)) {
            long value = ptrace_read(tid, addr);
            if (value == -1 && errno != 0) break;
            if (address_in_library(static_cast<uintptr_t>(value), segments)) return true;
        }
        return false;
    }
    
    // Scan from current stack pointer to end of stack
    for (uintptr_t addr = rsp; addr < stack.end; addr += sizeof(uintptr_t)) {
        long value = ptrace_read(tid, addr);
        if (value == -1 && errno != 0) break;
        if (address_in_library(static_cast<uintptr_t>(value), segments)) return true;
    }
    return false;
}

/**
 * @brief Check if a thread is currently using the specified library
 * @param tid Thread ID
 * @param segments Library memory segments
 * @return true if thread is inside library or has library pointers on stack
 * 
 * Used by is_safe_to_replace to determine if a thread might be affected
 * by library replacement.
 */
static bool thread_uses_library(pid_t tid, const std::vector<std::pair<uintptr_t, uintptr_t>>& segments) {
    if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == -1) {
        LOG_ERR("ptrace ATTACH failed for thread %d", tid);
        return true; // Assume unsafe if we can't check
    }
    
    int status;
    waitpid(tid, &status, 0);
    if (!WIFSTOPPED(status)) {
        LOG_WARN("Thread %d did not stop", tid);
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
        return true; // Assume unsafe
    }
    
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &regs) == -1) {
        LOG_ERR("ptrace GETREGS failed for thread %d", tid);
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
        return true; // Assume unsafe
    }
    
    bool uses = false;
    // Check if instruction pointer is inside library
    if (address_in_library(regs.rip, segments)) uses = true;
    // Check if stack contains pointers to library
    if (!uses && stack_contains_library(tid, regs.rsp, segments)) uses = true;
    
    ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
    return uses;
}

//=============================================================================
// DL_Manager public methods
//=============================================================================

/**
 * @brief Prepare a thread for remote code injection
 * @param tid Thread ID to prepare
 * @param prepared_regs [out] Registers after preparation (should be used for injection)
 * @return true if preparation succeeded
 * 
 * Performs two PTRACE_SYSCALL steps to ensure thread is not inside a syscall.
 * If thread is in a syscall when we inject code, the kernel will restart it
 * after detach, corrupting program state. This ensures we're at a safe point.
 * 
 * Why two syscall steps:
 * - First PTRACE_SYSCALL: If thread was in syscall, it exits and stops on exit
 *                         If not in syscall, it enters next syscall and stops on entry
 * - Second PTRACE_SYSCALL: Ensures we're stopped at a safe point (not in syscall)
 */
bool DL_Manager::prepare_thread_for_injection(pid_t tid, struct user_regs_struct& prepared_regs) {
    LOG_DBG("Preparing thread %d for injection", tid);

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

/**
 * @brief Wait for threads to leave a library and stop them
 * @param all_tids All thread IDs in process
 * @param segments Library segments to check
 * @param stopped_tids [out] Threads that were successfully stopped outside library
 * @param max_attempts Maximum number of retry attempts
 * @param retry_us Microseconds to wait between attempts
 * @return true if all threads eventually left the library
 * 
 * This function repeatedly checks threads until all are outside the library.
 * Threads found outside are stopped permanently; threads inside are detached
 * and retried later.
 */
bool DL_Manager::wait_for_threads_to_leave_library(const std::vector<pid_t>& all_tids,
                                                    const std::vector<std::pair<uintptr_t, uintptr_t>>& segments,
                                                    std::vector<pid_t>& stopped_tids,
                                                    int max_attempts, int retry_us) {
    stopped_tids.clear();
    std::set<pid_t> remaining(all_tids.begin(), all_tids.end());

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
                ++it;
            } else {
                LOG_DBG("Thread %d is outside library, stopping permanently", tid);
                stopped_tids.push_back(tid);
                it = remaining.erase(it);
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

/**
 * @brief Freeze all threads that are outside the target library
 * @param all_tids All thread IDs in process
 * @param segments Library segments to check
 * @param contexts [out] Thread contexts of successfully frozen threads
 * @return true if all threads were frozen outside the library
 * 
 * This function attempts to stop all threads while ensuring they are outside
 * the library. If any thread is inside, all are detached and the process retries.
 * This guarantees that when we return, all threads are stopped AND outside
 * the target library.
 */
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

/**
 * @brief Select a worker thread for remote code injection
 * @param contexts Vector of stopped thread contexts
 * @param worker_tid [out] Selected thread ID
 * 
 * Prefers the main thread (pid_) if available, otherwise uses the first thread.
 * The worker thread will execute our shellcode to load libraries.
 */
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
