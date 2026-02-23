#ifndef ARCH_HPP
#define ARCH_HPP

#if defined(__x86_64__)
#include "arch_x86_64.ipp"
// Here you can add your architecture module
// #elif defined(__new_arch__)
// #include "arch_new_arch.ipp"
#else
#error "Unsupported architecture"
#endif

#endif
