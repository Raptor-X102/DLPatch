#include "math_ops.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <unistd.h>
#include <cstdlib>
#include <ctime>
#include <dlfcn.h>


int main() {
    std::cout << "Target program running with PID: " << getpid() << std::endl;
    std::srand(std::time(nullptr));
    
    int counter = 0;
    while (true) {
        std::cout << "\n--- Iteration " << ++counter << " ---" << std::endl;
        
        double a = 10.0;
        double b = 5.0;
        
        double sum = add(a, b);
        std::cout << "add: " << sum << std::endl;
        
        double diff = subtract(a, b);
        std::cout << "subtract: " << diff << std::endl;
        
        double prod = multiply(a, b);
        std::cout << "multiply: " << prod << std::endl;
        
        double quot = divide(a, b);
        std::cout << "divide: " << quot << std::endl;
        
        double pow = power(a, 2.0);
        std::cout << "power (a^2): " << pow << std::endl;
        
        // Для v3 также попробуем modulus, если символ доступен
        // Используем dlsym для проверки наличия функции modulus
        void* handle = dlopen(NULL, RTLD_LAZY);
        if (handle) {
            typedef double (*mod_func)(int, int);
            mod_func mod = (mod_func)dlsym(handle, "modulus");
            if (mod) {
                double mod_result = mod(10, 3);
                std::cout << "modulus: " << mod_result << std::endl;
            }
            dlclose(handle);
        }
        
        std::cout << "perform_op: " << perform_op(a, b) << std::endl;
        
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }

    return 0;
}
