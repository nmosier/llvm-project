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

struct Stack {
  int64_t size;
  void *baseptr;
  void *stackptr;
  Stack *next;
  Stack *prev;
};

Stack *stack_tail = nullptr;

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

inline void fixup_stack_size(int64_t &size) {
  if (size == 0) {
    struct rlimit rlim;
    if (getrlimit(RLIMIT_STACK, &rlim) < 0)
      FPS_ABORT("getrlimit(RLIM_STACK) failed: %s\n", strerror(errno));
    size = rlim.rlim_cur;
  }
  assert(size > 0);
}

void alloc_stack(Stack &stack) {
  fixup_stack_size(stack.size);
  void *maybe_base = Mmap(nullptr, stack.size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (maybe_base == MAP_FAILED)
    FPS_ABORT("mmap failed: %s\n", strerror(errno));
  stack.baseptr = maybe_base;
  stack.stackptr = static_cast<char *>(stack.baseptr) + stack.size;
}

void free_stack(Stack &stack) {
  if (Munmap(stack.baseptr, stack.size) < 0)
    FPS_ABORT("munmap failed: %s\n", strerror(errno));
  stack.baseptr = nullptr;    
}

extern "C" __attribute__((visibility("default"))) void __fps_register(Stack *stack) {
  // Append to linked list.
  stack->prev = stack_tail;
  stack->next = nullptr;
  stack_tail = stack;

  // Map stack.
  alloc_stack(*stack);
}

extern "C" __attribute__((visibility("default"))) void __fps_deregister(Stack *stack) {
  // Remove from linked list.
  if (stack->prev)
    stack->prev->next = stack->next;
  if (stack->next)
    stack->next->prev = stack->prev;

  // Unmap stack.
  free_stack(*stack);
}

extern "C" __attribute__((visibility("default"))) __thread Stack __fps_unsafestack{};

static __attribute__((constructor(0))) void unsafestack_constructor() {
  __fps_register(&__fps_unsafestack);
}

static __attribute__((destructor(0))) void unsafestack_destructor() {
  __fps_deregister(&__fps_unsafestack);
}

}
