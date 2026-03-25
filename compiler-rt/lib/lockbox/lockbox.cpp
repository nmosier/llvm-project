#include <cstdlib>
#include <cstdio>
#include <sys/mman.h>
#include <immintrin.h>
#include <cstdint>

#define LOCKBOX_ABORT(a) std::abort()

#define LOCKBOX_CHECK(a)                                                       \
  do {                                                                         \
    if (!(a)) {                                                                \
      fprintf(stderr, "lockbox CHECK failed: %s:%d %s\n", __FILE__, __LINE__,  \
              #a);                                                             \
      LOCKBOX_ABORT();                                                         \
    }                                                                   \
  } while (false)

extern "C" int32_t __lockbox_pkey = -1;

namespace __lockbox {

namespace {

__attribute__((constructor(0))) void init(void) {
  // Allocate a fresh key and disable access.
  __lockbox_pkey = pkey_alloc(0, PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE);
  LOCKBOX_CHECK(__lockbox_pkey >= 0);
}

__attribute__((destructor(0))) void deinit(void) {
  if (__lockbox_pkey >= 0) {
    pkey_free(__lockbox_pkey);
  }
}

}

}
