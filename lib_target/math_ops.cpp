#include "math_ops.h"
#include <iostream>
#include <cmath>

double add(double a, double b) {
    std::cout << "[MATH_LIB v1] Adding " << a << " + " << b << std::endl;
    return a + b;
}

double subtract(double a, double b) {
    std::cout << "[MATH_LIB v1] Subtracting " << a << " - " << b << std::endl;
    return a - b;
}

double multiply(double a, double b) {
    std::cout << "[MATH_LIB v1] Multiplying " << a << " * " << b << std::endl;
    return a * b;
}

double divide(double a, double b) {
    if (b == 0) {
        std::cerr << "[MATH_LIB v1] Error: Division by zero!" << std::endl;
        return 0;
    }
    std::cout << "[MATH_LIB v1] Dividing " << a << " / " << b << std::endl;
    return a / b;
}

double power(double base, double exp) {
    std::cout << "[MATH_LIB v1] Power " << base << " ^ " << exp << std::endl;
    return std::pow(base, exp);
}

// Для обратной совместимости
double perform_op(double a, double b) {
    return add(a, b);
}
