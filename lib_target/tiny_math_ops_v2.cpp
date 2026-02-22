#include "tiny_math_ops.h"
#include <iostream>

int zero() {
    std::cout << "[TINY v2] zero() -> 100" << std::endl;
    return 100;
}

int one() {
    std::cout << "[TINY v2] one() -> 200" << std::endl;
    return 200;
}

int forty_two() {
    std::cout << "[TINY v2] forty_two() -> 42 (unchanged)" << std::endl;
    return 42;
}

int max(int a, int b) {
    int result = (a < b) ? a : b;
    std::cout << "[TINY v2] max(" << a << ", " << b << ") -> " << result << std::endl;
    return result;
}

double add(double a, double b) {
    double result = a + b + 1.0;
    std::cout << "[TINY v2] add(" << a << ", " << b << ") + 1 = " << result << std::endl;
    return result;
}

int test_internal(int a, int b) {
    return zero() + one() + forty_two() + max(a, b);
}
