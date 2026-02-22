#include "tiny_math_ops.h"
#include <iostream>

int zero() {
    return 0;
}

int one() {
    return 1;
}

int forty_two() {
    return 42;
}

int max(int a, int b) {
    return (a > b) ? a : b;
}

double add(double a, double b) {
    std::cout << "[TINY v1] add(" << a << ", " << b << ") = " << a + b << std::endl;
    return a + b;
}

// Внутренняя функция, создающая вызовы маленьких функций через PLT
int test_internal(int a, int b) {
    return zero() + one() + forty_two() + max(a, b);
}
