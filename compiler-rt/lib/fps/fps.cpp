#include "interception/interception.h"
#include <stdio.h>
#include <stdint.h>
#include "safestack/safestack_util.h"

/// Default size of function-private stacks.
const unsigned kDefaultFPSSize = 0x10000;

#if 0
// NHM-FIXME: Use size_t rather than uint64_t?
extern "C" __attribute__((visibility("default"))) void *__fps_alloc(uint64_t size, uint64_t guard) {
  size_t size = kDefaultFPSSize;
  Mmap(nullptr, size + guar
}

#endif
