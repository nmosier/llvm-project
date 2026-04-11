#pragma once

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" {

extern bool __lockbox_enabled;

void __lockbox_access_enable(void);
void __lockbox_access_disable(void);
void *__lockbox_malloc(size_t size);
void __lockbox_free(void *ptr);
bool __lockbox_access_enabled(void);

}

namespace __lockbox {

extern int pkey;
void InitAllocator();

}

#define LOCKBOX_ABORT(a) abort()

#define LOCKBOX_CHECK(a)                                                       \
  do {                                                                         \
    if (!(a)) {                                                                \
      fprintf(stderr, "lockbox CHECK failed: %s:%d %s\n", __FILE__, __LINE__,  \
              #a);                                                             \
      LOCKBOX_ABORT();                                                         \
    }                                                                          \
  } while (false)

#define LOCKBOX_LOG(...)                                                       \
  do {                                                                         \
  } while (false)
