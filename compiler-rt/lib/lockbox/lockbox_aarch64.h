#pragma once

#if !defined(__aarch64__)
#error "Not AArch64!"
#endif

#include <stdint.h>

using pkey_mask_t = uint64_t;

static inline pkey_mask_t arch_pkey_enable_mask(int pkey) {
  return pkey_mask_t(0b111) << 4;
}

static inline void set_pkru(pkey_mask_t mask) {
  asm volatile ("msr POR_EL0, %0" :: "r"(mask));
}

static inline pkey_mask_t get_pkru(void) {
  pkey_mask_t pkru;
  asm("mrs %0, POR_EL0" : "=r"(pkru));
  return pkru;
}

// Returns a mask that semantically is the union of permissions in masks \p a and \p b.
static inline pkey_mask_t pkey_mask_union(pkey_mask_t a, pkey_mask_t b) {
  return a | b;
}

// Returns a mask that semantically is the interscetion of permissions in masks
// \p a and \p b.
static inline pkey_mask_t pkey_mask_intersect(pkey_mask_t a, pkey_mask_t b) {
  return a & b;
}