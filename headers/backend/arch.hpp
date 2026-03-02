//=============================================================================
// arch.hpp
// Architecture abstraction layer - selects appropriate implementation
//=============================================================================

#ifndef ARCH_HPP
#define ARCH_HPP

#if defined(__x86_64__)
#include "arch_x86_64.ipp"
// Future architecture support can be added here:
// #elif defined(__aarch64__)
// #include "arch_aarch64.ipp"
// #elif defined(__arm__)
// #include "arch_arm.ipp"
#else
#error "Unsupported architecture - currently only x86_64 is supported"
#endif

#endif
