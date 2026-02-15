#include "math_ops.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <unistd.h>

int main() {
    std::cout << "Target program running with PID: " << getpid() << std::endl;

    while (true) {
        double result = perform_op(10.0, 5.0);
        std::cout << "Result: " << result << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    return 0;
}
