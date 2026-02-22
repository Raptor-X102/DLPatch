#include <sys/uio.h>
#include <cstring>
#include <string>

static bool read_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size) {
    struct iovec local = {buffer, size};
    struct iovec remote = {reinterpret_cast<void*>(addr), size};
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    return n == static_cast<ssize_t>(size);
}

template<typename T>
static bool read_struct(pid_t pid, uintptr_t addr, T& value) {
    return read_process_memory(pid, addr, &value, sizeof(T));
}

static std::string read_string(pid_t pid, uintptr_t addr, size_t max_len = 256) {
    std::string result;
    char ch;
    for (size_t i = 0; i < max_len; ++i) {
        if (!read_struct(pid, addr + i, ch) || ch == '\0') break;
        result.push_back(ch);
    }
    return result;
}

static bool address_in_library(uintptr_t addr, const std::vector<std::pair<uintptr_t, uintptr_t>>& segments) {
    for (const auto& seg : segments) {
        if (addr >= seg.first && addr < seg.second) return true;
    }
    return false;
}
