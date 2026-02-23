// headers/backend/logging.hpp
#ifndef LOGGING_HPP
#define LOGGING_HPP

#include <cstdio>
#include <iostream>

// Always print errors to stderr
#define LOG_ERR(fmt, ...) \
    fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)

// Always print warnings to stderr
#define LOG_WARN(fmt, ...) \
    fprintf(stderr, "[WARN]  " fmt "\n", ##__VA_ARGS__)

// Always print results (success/failure) to stdout
#define LOG_RESULT(fmt, ...) \
    printf("[RESULT] " fmt "\n", ##__VA_ARGS__)

// Info messages – shown unless NDEBUG is defined
#ifndef NDEBUG
#define LOG_INFO(fmt, ...) \
    printf("[INFO]  " fmt "\n", ##__VA_ARGS__)
#else
#define LOG_INFO(fmt, ...) 
#endif

// Debug messages – shown only if DEBUG is defined
#ifdef DEBUG
#define LOG_DBG(fmt, ...) \
    printf("[DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define LOG_DBG(fmt, ...) 
#endif

#endif // LOGGING_HPP
