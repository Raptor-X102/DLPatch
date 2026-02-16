#ifndef MATH_OPS_H
#define MATH_OPS_H

#ifdef __cplusplus
extern "C" {
#endif

double add(double a, double b);
double subtract(double a, double b);
double multiply(double a, double b);
double divide(double a, double b);
double power(double base, double exp);
double perform_op(double a, double b); // сохраняем для обратной совместимости

#ifdef __cplusplus
}
#endif

#endif // MATH_OPS_H
