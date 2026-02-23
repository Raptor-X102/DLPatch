#ifndef LOGGING_HPP
#define LOGGING_HPP

#include <cstdio>
#include <iostream>

// ============================================================
// ALWAYS VISIBLE LOGS (even in release builds)
// These are critical for users to understand what's happening
// ============================================================

// Errors - always shown, critical failures
#define LOG_ERR(fmt, ...) fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)

// Warnings - always shown, non-critical but important
#define LOG_WARN(fmt, ...) fprintf(stderr, "[WARN]  " fmt "\n", ##__VA_ARGS__)

// Results - always shown, operation outcome
#define LOG_RESULT(fmt, ...) printf("[RESULT] " fmt "\n", ##__VA_ARGS__)

// Info - always shown, normal operation information
// Users need to see what's happening: library loading, patching, etc.
#define LOG_INFO(fmt, ...) printf("[INFO]  " fmt "\n", ##__VA_ARGS__)

// ============================================================
// DEBUG ONLY LOGS (only when DEBUG is defined)
// These are for developers debugging internal issues
// ============================================================

#ifdef DEBUG
// Detailed debug information
#define LOG_DBG(fmt, ...) printf("[DEBUG] " fmt "\n", ##__VA_ARGS__)

// Very verbose debug (memory dumps, register values, etc.)
#define LOG_VERBOSE(fmt, ...) printf("[VERB]  " fmt "\n", ##__VA_ARGS__)

// Trace function entry/exit
#define LOG_TRACE(fmt, ...) printf("[TRACE] " fmt "\n", ##__VA_ARGS__)
#else
#define LOG_DBG(fmt, ...)
#define LOG_VERBOSE(fmt, ...)
#define LOG_TRACE(fmt, ...)
#endif

#endif // LOGGING_HPP
