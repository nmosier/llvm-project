#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include "safestack/safestack_util.h"
#include "safestack/safestack_platform.h"
#include "fps/fps_util.h"

namespace fps {
namespace {

/// Default size of function-private stacks.
const unsigned kDefaultFPSSize = 0x80000;
const unsigned kGuardSize = getpagesize();
const unsigned kStackAlign = 16;

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

size_t map_length = 0;

size_t getVecSize() {
  return map_length / sizeof(void *);
}

#if 0

extern "C" __attribute__((visibility("default"))) thread_local FunctionPrivateStack *__fps_thdstacks = nullptr;

struct thread_ll {
  PinnedVector<FunctionPrivateStack> stacks;
  thread_ll *next;

  thread_ll(size_t num_stacks, thread_ll *next = nullptr): stacks(num_stacks), next(next) {}
};

thread_ll *threads;

// NHM-FIXME: Is there a cleaner way to do this? 
__attribute__((constructor(0))) void init_main_thread() {
  if (threads)
    return;
  
  threads = (thread_ll *) malloc(sizeof(thread_ll));
  FPS_CHECK(threads);
  new (threads) thread_ll(num_stacks);
  __fps_thdstacks = threads->stacks.getData();
  fprintf(stderr, "__fps_thdstacks = %p\n", __fps_thdstacks);
}

// NHM-FIXME: Needs to take size arguments.
extern "C" __attribute__((visibility("default"))) uint64_t __fps_regstack() {
  init_main_thread();
  
  const size_t size = kDefaultFPSSize;
  bool index_valid = false;
  uint64_t index;
  for (thread_ll *thread = threads; thread; thread = thread->next) {
    FunctionPrivateStack fps;
    fps.allocate(size, kGuardSize);
    const uint64_t new_index = thread->stacks.insert(static_cast<FunctionPrivateStack &&>(fps));
    if (index_valid) {
      FPS_CHECK(index == new_index);
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

#endif




extern "C" __attribute__((visibility("default"))) thread_local void **__fps_thd_stackptrs = nullptr;
extern "C" __attribute__((visibility("default"))) thread_local void **__fps_thd_stackbases = nullptr;
extern "C" __attribute__((visibility("default"))) thread_local uint64_t *__fps_thd_stacksizes = nullptr;

class Thread {
public:
  void **stackptrs;
  void **stackbases;
  uintptr_t *stacksizes;
  Thread *next;

private:
  static size_t CalculateMinSize(size_t num_stacks) {
    return align_up<size_t>(max<size_t>(1, num_stacks * sizeof(void *)), getpagesize());
  }

  template <typename T>
  T *CreateNewMap() {
    static_assert(sizeof(T) == sizeof(void *), "");
    FPS_CHECK(map_length % sizeof(T) == 0);
    T *map = static_cast<T *>(safestack::Mmap(nullptr, map_length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
    FPS_CHECK(map != MAP_FAILED);
    return map;
  }

  template <typename T>
  static void growOne(T *&map) {
    void *old_map = map;
    void *new_map = Mremap(old_map, map_length, map_length * 2);
    if (new_map == MAP_FAILED && errno == ENOMEM) {
      new_map = safestack::Mmap(old_map, map_length * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
      FPS_CHECK(map != MAP_FAILED);
      memcpy(new_map, old_map, map_length);
      // NHM-FIXME: Figure out a way to do this.
      // Munmap(map, map_length, map_length * 2);
      safestack::Mprotect(old_map, map_length, PROT_READ);
    }
    map = (T *) new_map;
  }

public:

  Thread(Thread *next): next(next) {
    stackptrs = CreateNewMap<void *>();
    stackbases = CreateNewMap<void *>();
    stacksizes = CreateNewMap<uintptr_t>();
  }

  void grow() {
    growOne(stackptrs); __fps_thd_stackptrs = stackptrs;
    growOne(stackbases); __fps_thd_stackbases = stackbases;
    growOne(stacksizes); __fps_thd_stacksizes = stacksizes;
  }

  void allocateStack(size_t index, size_t stacksize, size_t guardsize) {
    FPS_CHECK(index < getVecSize());
    // NHM-FIXME: Do guard.
    void *stackbase = safestack::Mmap(nullptr, stacksize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    FPS_CHECK(stackbase != MAP_FAILED);
    stacksizes[index] = stacksize;
    stackbases[index] = stackbase;
    stackptrs[index] = static_cast<char *>(stackbase) + stacksize;
    FPS_LOG("allocated stack at %p", stackbase);
  }

  void deallocateStack(size_t index) {
    FPS_CHECK(index < getVecSize());
    FPS_CHECK(stacksizes[index] > 0);
    safestack::Munmap(nullptr, stacksizes[index]);
    stacksizes[index] = 0;
    stackbases[index] = nullptr;
    stackptrs[index] = nullptr;
  }
};

Thread *threads = nullptr;

__attribute__((constructor(0))) void init_main_thread() {
  if (threads)
    return;
  
  map_length = getpagesize(); // NHM-FIXME: Maybe hard-code it instead?
  threads = new (malloc(sizeof(Thread))) Thread(threads);
  __fps_thd_stackptrs = threads->stackptrs;
  __fps_thd_stackbases = threads->stackbases;
  __fps_thd_stacksizes = threads->stacksizes;
}

size_t getUnusedIndex() {
  size_t i;
  for (i = 0; i < getVecSize(); ++i)
    if (!__fps_thd_stackptrs[i])
      return i;
  for (Thread *thread = threads; thread; thread = thread->next)
    thread->grow();
  map_length += getpagesize();
  FPS_CHECK(i < getVecSize());
  return i;
}

extern "C" __attribute__((visibility("default"))) uint64_t __fps_regstack() {
  init_main_thread();
  
  const size_t index = getUnusedIndex();
  const size_t stacksize = kDefaultFPSSize;
  const size_t guardsize = getpagesize(); // NHM-FIXME
  for (Thread *thread = threads; thread; thread = thread->next)
    thread->allocateStack(index, stacksize, guardsize);
  FPS_LOG("registered index %" PRIu64, index);
  return index * sizeof(void *); // NHM-FIXME
}

extern "C" __attribute__((visibility("default"))) void __fps_deregstack(uint64_t index) {
  index /= sizeof(void *); // NHM-FIXME: This should be moved into FPS's generated consturctor/destructor code, instead.
  for (Thread *thread = threads; thread; thread = thread->next)
    thread->deallocateStack(index);
  FPS_LOG("deregistered index %" PRIu64, index);
}

struct tinfo {
  Thread *thread;
  void *(*start_routine)(void *);
  void *arg;

  tinfo(Thread *thread, void *(*start_routine)(void *), void *arg):
      thread(thread), start_routine(start_routine), arg(arg) {}
};

void *thread_start(void *arg) {
  tinfo *thd_info = (tinfo *) arg;
  __fps_thd_stackptrs = threads->stackptrs;
  __fps_thd_stackbases = threads->stackbases;
  __fps_thd_stacksizes = threads->stacksizes;
  return thd_info->start_routine(thd_info->arg);
}

extern "C" __attribute__((weak, alias("__interceptor_pthread_create"), visibility("default"))) int pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);

extern "C" __attribute__((weak, visibility("default"))) int ___interceptor_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg) {
  typedef int pthread_create_t(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
  pthread_create_t *sym = (pthread_create_t *) dlsym(RTLD_NEXT, "pthread_create");
  FPS_CHECK(sym);
  return sym(thread, attr, start_routine, arg);
}

extern "C" __attribute__((visibility("default"))) int __interceptor_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg)  {
  FPS_LOG("[fps] intercepted pthread_create");

  // Create a new thread.
  size_t size = kDefaultFPSSize;
  size_t guard = getpagesize(); // NHM-FIXME
  Thread *ref_thread = threads;
  Thread *new_thread = new (malloc(sizeof(Thread))) Thread(threads);
  for (size_t i = 0; i < getVecSize(); ++i)
    if (ref_thread->stacksizes[i])
      new_thread->allocateStack(i, size, guard);
  threads = new_thread;

  tinfo *thd_info = new (malloc(sizeof(tinfo))) tinfo(new_thread, start_routine, arg);
  FPS_CHECK(thd_info);

  return ___interceptor_pthread_create(thread, attr, thread_start, thd_info);
}


}
}

int get_errno() {
  return errno;
}

