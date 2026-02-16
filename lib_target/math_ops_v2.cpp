#include "math_ops.h"
#include <iostream>
#include <cmath>

double add(double a, double b) {
    std::cout << "[MATH_LIB v2] Adding " << a << " + " << b << " = " << (a + b) << std::endl;
    return a + b;
}

double subtract(double a, double b) {
    std::cout << "[MATH_LIB v2] Subtracting " << a << " - " << b << " = " << (a - b) << std::endl;
    return a - b;
}

double multiply(double a, double b) {
    std::cout << "[MATH_LIB v2] Multiplying " << a << " * " << b << " = " << (a * b) << std::endl;
    return a * b;
}

double divide(double a, double b) {
    if (b == 0) {
        std::cerr << "[MATH_LIB v2] Error: Division by zero!" << std::endl;
        return 0;
    }
    double result = a / b;
    std::cout << "[MATH_LIB v2] Dividing " << a << " / " << b << " = " << result << std::endl;
    return result;
}

double power(double base, double exp) {
    double result = std::pow(base, exp);
    std::cout << "[MATH_LIB v2] Power " << base << " ^ " << exp << " = " << result << std::endl;
    return result;
}

double perform_op(double a, double b) {
    std::cout << "[MATH_LIB v2] Performing operation (add) on " << a << " and " << b << std::endl;
    return add(a, b);
}
