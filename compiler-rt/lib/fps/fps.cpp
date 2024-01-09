#include "interception/interception.h"
#include <stdio.h>
#include <stdint.h>
#include "safestack/safestack_util.h"
#include "safestack/safestack_platform.h"
#include "fps/fps_util.h"

namespace fps {
namespace {

/// Default size of function-private stacks.
const unsigned kDefaultFPSSize = 0x10000;
const unsigned kGuardSize = getpagesize();

#if 0
// NHM-FIXME: Use size_t rather than uint64_t?
extern "C" __attribute__((visibility("default"))) void *__fps_alloc(uint64_t size, uint64_t guard) {
  size_t size = kDefaultFPSSize;
}

#endif

#if 0
typedef uint64_t setjmp_ctx_cb_size(void);
typedef uint64_t setjmp_ctx_cb_save(void *);
typedef uint64_t setjmp_ctx_cb_restore(void *);

struct setjmp_ctx_ll {
  uint64_t (*size)(void);
  uint64_t (*save)(void *);
  uint64_t (*restore)(const void *);
  setjmp_ctx_ll *prev;
  setjmp_ctx_ll *next;
};

setjmp_ctx_ll *setjmp_ctx_root;

extern "C" __attribute__((visibility("default"))) void __fps_setjmp_ctx_register(setjmp_ctx_ll *ctx) {
  ctx->prev = nullptr;
  ctx->next = setjmp_ctx_root;
  ctx->next->prev = ctx;
  setjmp_ctx_root = ctx;
}

extern "C" __attribute__((visibility("default"))) void __fps_setjmp_ctx_deregister(setjmp_ctx_ll *ctx) {
  if (ctx->prev)
    ctx->prev->next = ctx->next;
  else
    setjmp_ctx_root = ctx->next;
  if (ctx->next)
    ctx->next->prev = ctx->prev;
}

extern "C" __attribute__((visibility("default"))) uint64_t __fps_setjmp_ctx_size(void) {
  uint64_t size = 0;
  for (const setjmp_ctx_ll *it = setjmp_ctx_root; it; it = it->next)
    size += it->size();
  return size;
}

extern "C" __attribute__((visibility("default"))) uint64_t __fps_setjmp_ctx_save(void *buf) {
  uint64_t size = 0;
  for (const setjmp_ctx_ll *it = setjmp_ctx_root; it; it = it->next)
    size += it->save((char *) buf + size);
  return size;
}

extern "C" __attribute__((visibility("default"))) uint64_t __fps_setjmp_ctx_restore(const void *buf) {
  uint64_t size = 0;
  for (const setjmp_ctx_ll *it = setjmp_ctx_root; it; it = it->next)
    size += it->restore((const char *) buf + size);
  return size;
}
#endif

struct FunctionPrivateStack {
  uintptr_t size;
  void *base;
  void *ptr;

  FunctionPrivateStack(): size(0) {}

  FunctionPrivateStack &operator=(FunctionPrivateStack &&other) {
    if (valid())
      deallocate();
    size = other.size;
    base = other.base;
    ptr = other.ptr;
    other.size = 0;
    return *this;
  }

  ~FunctionPrivateStack() {
    if (valid())
      deallocate();
  }

  void allocate(size_t size, size_t guard) {
    this->size = size;
    base = safestack::Mmap(nullptr, size + guard, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    FPS_CHECK(base != MAP_FAILED);
    safestack::Mprotect(base, guard, PROT_NONE);
    // NHM-FIXME: Guard on other side?
    ptr = static_cast<uint8_t *>(base) + size - guard;

    fprintf(stderr, "allocated FPS @ %p with size %zu\n", base, size);
  }

  void deallocate() {
    safestack::Munmap(base, size);
    size = 0;
  }

  bool valid() const {
    return size > 0;
  }

  operator bool() const {
    return valid();
  }
};


static size_t num_stacks = 0;

extern "C" __attribute__((visibility("default"))) thread_local FunctionPrivateStack *__fps_thdstacks = nullptr;

struct thread_ll {
  PinnedVector<FunctionPrivateStack> stacks;
  thread_ll *next;

  thread_ll(size_t num_stacks, thread_ll *next = nullptr): stacks(num_stacks), next(next) {}
};

thread_ll *threads;

// NHM-FIXME: Is there a cleaner way to do this? 
__attribute__((constructor(0))) void init_main_thread() {
  threads = (thread_ll *) malloc(sizeof(thread_ll));
  FPS_CHECK(threads);
  new (threads) thread_ll(num_stacks);
  __fps_thdstacks = threads->stacks.getData();
  fprintf(stderr, "__fps_thdstacks = %p\n", __fps_thdstacks);
}

// NHM-FIXME: Needs to take size arguments.
extern "C" __attribute__((visibility("default"))) uint64_t __fps_regstack() {
  const size_t size = kDefaultFPSSize;
  bool index_valid = false;
  uint64_t index;
  for (thread_ll *thread = threads; thread; thread = thread->next) {
    FunctionPrivateStack fps;
    fps.allocate(size, kGuardSize);
    const uint64_t new_index = thread->stacks.insert(static_cast<FunctionPrivateStack &&>(fps));
    if (index_valid) {
      assert(index == new_index);
    } else {
      index = new_index;
      index_valid = true;
    }
  }
  return index;
}

extern "C" __attribute__((visibility("default"))) void __fps_deregstack(uint64_t index) {
  for (thread_ll *thread = threads; thread; thread = thread->next) {
    thread->stacks[index].deallocate();
  }
}

}
}
