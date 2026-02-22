#include "tiny_math_ops.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <random>
#include <atomic>
#include <unistd.h>

std::atomic<int> g_counter{0};

void worker_function(int id) {
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(0, 100);
    
    while (true) {
        int a = dist(rng);
        int b = dist(rng);
        
        int z = zero();
        int o = one();
        int ft = forty_two();
        int m = max(a, b);
        
        if (g_counter++ % 100 == 0) {
            std::cout << "Thread " << id << ": zero=" << z
                      << ", one=" << o
                      << ", forty_two=" << ft
                      << ", max(" << a << "," << b << ")=" << m << std::endl;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

int main() {
    std::cout << "Target program (tiny) running with PID: " << getpid() << std::endl;
    
    const int NUM_WORKERS = 2;
    std::vector<std::thread> workers;
    for (int i = 0; i < NUM_WORKERS; ++i) {
        workers.emplace_back(worker_function, i + 1);
    }
    
    int counter = 0;
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        std::cout << "\n--- Main iteration " << ++counter << " ---" << std::endl;
        
        double x = 10.0, y = 5.0;
        std::cout << "add: " << add(x, y) << std::endl;
    }
    
    return 0;
}
