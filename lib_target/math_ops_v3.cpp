#include "math_ops.h"
#include <iostream>
#include <cmath>

double add(double a, double b) {
    std::cout << "[MATH_LIB v3] ADD: " << a << " + " << b << " = " << (a + b)
              << std::endl;
    return a + b;
}

double subtract(double a, double b) {
    std::cout << "[MATH_LIB v3] SUB: " << a << " - " << b << " = " << (a - b)
              << std::endl;
    return a - b;
}

double multiply(double a, double b) {
    std::cout << "[MATH_LIB v3] MUL: " << a << " * " << b << " = " << (a * b)
              << std::endl;
    return a * b;
}

double divide(double a, double b) {
    if (b == 0) {
        std::cerr << "[MATH_LIB v3] ERROR: Division by zero!" << std::endl;
        return 0;
    }
    double result = a / b;
    std::cout << "[MATH_LIB v3] DIV: " << a << " / " << b << " = " << result
              << std::endl;
    return result;
}

double power(double base, double exp) {
    double result = std::pow(base, exp);
    std::cout << "[MATH_LIB v3] POW: " << base << " ^ " << exp << " = " << result
              << std::endl;
    return result;
}

// Добавляем новую функцию
double modulus(int a, int b) {
    if (b == 0) {
        std::cerr << "[MATH_LIB v3] ERROR: Modulus by zero!" << std::endl;
        return 0;
    }
    int result = a % b;
    std::cout << "[MATH_LIB v3] MOD: " << a << " % " << b << " = " << result
              << std::endl;
    return result;
}

double perform_op(double a, double b) {
    std::cout << "[MATH_LIB v3] perform_op calls add" << std::endl;
    return add(a, b);
}
