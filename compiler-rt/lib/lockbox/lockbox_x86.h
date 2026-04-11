#pragma once

#if !defined(__x86_64__)
#error "Not x86-64!"
#endif

#include <stdint.h>

using pkey_mask_t = uint32_t;

static inline pkey_mask_t arch_pkey_enable_mask(int pkey) {
  return ~(pkey_mask_t(3) << (pkey * 2));
}

static inline void set_pkru(pkey_mask_t mask) {
  asm volatile("wrpkru" :: "a"(mask), "c"(0), "d"(0));
}

static inline pkey_mask_t get_pkru(void) {
  pkey_mask_t mask;
  asm("rdpkru" : "=a"(mask) : "c"(0) : "rdx");
  return mask;
}

// Returns a mask that semantically is the union of permissions in masks \p a and \p b.
static inline pkey_mask_t pkey_mask_union(pkey_mask_t a, pkey_mask_t b) {
  return a & b;
}

// Returns a mask that semantically is the interscetion of permissions in masks
// \p a and \p b.
static inline pkey_mask_t pkey_mask_intersect(pkey_mask_t a, pkey_mask_t b) {
  return a | b;
}