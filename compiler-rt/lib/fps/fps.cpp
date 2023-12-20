#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/resource.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define FPS_ABORT(...)                                                  \
  do {                                                                  \
    fprintf(stderr, "function-private stack sanitizer: " __VA_ARGS__);  \
    abort();                                                            \
  } while (0)

namespace {

void *Mmap(void *addr, size_t length, int prot, int flags, int fd,
           off_t offset) {
#if SANITIZER_NETBSD
  return __mmap(addr, length, prot, flags, fd, 0, offset);
#elif SANITIZER_FREEBSD && (defined(__aarch64__) || defined(__x86_64__))
  return (void *)__syscall(SYS_mmap, addr, length, prot, flags, fd, offset);
#else
  return (void *)syscall(SYS_mmap, addr, length, prot, flags, fd, offset);
#endif
}

int Munmap(void *addr, size_t length) {
#if SANITIZER_NETBSD
  DEFINE__REAL(int, munmap, void *a, size_t b);
  return _REAL(munmap, addr, length);
#else
  return syscall(SYS_munmap, addr, length);
#endif
}

inline void fixup_stack_size(size_t *size) {
  if (*size == 0) {
    struct rlimit rlim;
    if (getrlimit(RLIMIT_STACK, &rlim) < 0)
      FPS_ABORT("getrlimit(RLIM_STACK) failed: %s\n", strerror(errno));
    *size = rlim.rlim_cur;
  }
  assert(*size > 0);
}

}

extern "C" __attribute__((visibility("default"))) void __fps_allocstack(void **base, size_t *size) {
  fixup_stack_size(size);
  void *maybe_base = Mmap(nullptr, *size, PROT_READ | PROT_WRITE,
                          MAP_STACK | MAP_GROWSDOWN | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (maybe_base == MAP_FAILED)
    FPS_ABORT("mmap failed: %s\n", strerror(errno));
  *base = maybe_base;
}

extern "C" __attribute__((visibility("default"))) void __fps_freestack(void **base, size_t *size) {
  if (Munmap(*base, *size) < 0)
    FPS_ABORT("munmap failed: %s\n", strerror(errno));
  *base = nullptr;
}
