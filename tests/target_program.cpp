#include "math_ops.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <unistd.h>
#include <cstdlib>
#include <ctime>
#include <dlfcn.h>
#include <vector>
#include <random>
#include <atomic>

// Thread-local random number generators for worker threads
thread_local std::mt19937 rng(std::random_device{}());
thread_local std::uniform_real_distribution<> dist(1.0, 10.0);
std::atomic<int> g_counter{0};

void worker_function(int /*id*/) {  // id unused, kept for potential future use
    double accumulator = 0.0;
    int iterations = 0;
    
    while (true) {
        double x = dist(rng);
        double y = dist(rng);
        
        // Call math functions to keep library in use
        double res1 = add(x, y);
        double res2 = subtract(x, y);
        double res3 = multiply(x, y);
        double res4 = divide(x, y);
        
        // Accumulate results to prevent optimization
        accumulator += res1 + res2 + res3 + res4;
        iterations++;
        g_counter++;
        
        // No output from worker threads – only main thread prints
        
        // Sleep to control call frequency (approx 2 calls per second)
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

int main() {
    std::cout << "Target program running with PID: " << getpid() << std::endl;
    std::srand(std::time(nullptr));
    
    const int NUM_WORKERS = 3;
    std::vector<std::thread> workers;
    for (int i = 0; i < NUM_WORKERS; ++i) {
        workers.emplace_back(worker_function, i + 1);
    }
    
    int counter = 0;
    while (true) {
        std::cout << "\n--- Main iteration " << ++counter << " ---" << std::endl;
        std::cout << "Total worker calls: " << g_counter.load() << std::endl;
        
        double a = 10.0;
        double b = 5.0;
        
        std::cout << "add: " << add(a, b) << std::endl;
        std::cout << "subtract: " << subtract(a, b) << std::endl;
        std::cout << "multiply: " << multiply(a, b) << std::endl;
        std::cout << "divide: " << divide(a, b) << std::endl;
        std::cout << "power (a^2): " << power(a, 2.0) << std::endl;
        
        // Try to use modulus if available (v3 only)
        void* handle = dlopen(NULL, RTLD_LAZY);
        if (handle) {
            typedef double (*mod_func)(int, int);
            mod_func mod = (mod_func)dlsym(handle, "modulus");
            if (mod) {
                std::cout << "modulus: " << mod(10, 3) << std::endl;
            }
            dlclose(handle);
        }
        
        std::cout << "perform_op: " << perform_op(a, b) << std::endl;
        
        // Main loop iteration every 5 seconds
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    // Join threads (never reached, but for completeness)
    for (auto& t : workers) {
        t.join();
    }
    return 0;
}
