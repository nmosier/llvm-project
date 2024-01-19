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

void thread_cleanup_handler(void *_iter);

/// Default size of function-private stacks.
const unsigned kDefaultFPSSize = 0x100000;
const unsigned kGuardSize = getpagesize();
const unsigned kStackAlign = 16;

size_t map_length = 0;

size_t getVecSize() {
  return map_length / sizeof(void *);
}

extern "C" __attribute__((visibility("default"))) thread_local void **__fps_thd_stackptrs = nullptr;
extern "C" __attribute__((visibility("default"))) thread_local void **__fps_thd_stackbases = nullptr;
extern "C" __attribute__((visibility("default"))) thread_local uint64_t *__fps_thd_stacksizes = nullptr;
const char **names = nullptr;

class Thread {
public:
  pid_t pid = -1;
  pid_t tid = -1;
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
    return (T *) Mmap(nullptr, map_length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON);
  }

  template <typename T>
  static void growOne(T *&map) {
    void *old_map = map;
    void *new_map = Mremap(old_map, map_length, map_length * 2);
    if (new_map == MAP_FAILED) {
      if (errno != ENOMEM) {
        fprintf(stderr, "[fps] mremap failed: %s\n", strerror(errno));
      }
      new_map = Mmap(old_map, map_length * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON);
      memcpy(new_map, old_map, map_length);
      // NHM-FIXME: Figure out a way to do this.
      // Munmap(map, map_length, map_length * 2);
      Mprotect(old_map, map_length, PROT_READ);
    }
    map = (T *) new_map;
  }

  void Unmap(void *map, size_t length) {
    safestack::Munmap(map, length);
  }
  
public:

  Thread(Thread *next): next(next) {
    stackptrs = CreateNewMap<void *>();
    stackbases = CreateNewMap<void *>();
    stacksizes = CreateNewMap<uintptr_t>();
    pid = getpid();
  }

  ~Thread() {
    for (size_t i = 0; i < getVecSize(); ++i)
      if (stacksizes[i] > 0)
        Unmap(stackbases[i], stacksizes[i]);
    Unmap(stackptrs, map_length);
    Unmap(stackbases, map_length);
    Unmap(stacksizes, map_length);
  }

  void grow() {
    growOne(stackptrs); __fps_thd_stackptrs = stackptrs;
    growOne(stackbases); __fps_thd_stackbases = stackbases;
    growOne(stacksizes); __fps_thd_stacksizes = stacksizes;
  }

  void allocateStack(size_t index, size_t stacksize, size_t guardsize) {
    FPS_CHECK(index < getVecSize());
    // NHM-FIXME: Do guard.
    void *stackbase = Mmap(nullptr, stacksize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON);
    stacksizes[index] = stacksize;
    stackbases[index] = stackbase;
    stackptrs[index] = static_cast<char *>(stackbase) + stacksize;
    FPS_LOG("allocated stack for %s at %p-%p", names[index], stackbase, (char *) stackbase + stacksize);
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
pthread_mutex_t threads_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_key_t thread_cleanup_key;
thread_local Thread *__fps_thread = nullptr;

__attribute__((constructor(0))) void init_main_thread() {
  Lock threads_lock(threads_mutex);
  if (threads)
    return;
  
  map_length = getpagesize(); // NHM-FIXME: Maybe hard-code it instead?
  __fps_thread = threads = new (malloc(sizeof(Thread))) Thread(threads);
  __fps_thd_stackptrs = threads->stackptrs;
  __fps_thd_stackbases = threads->stackbases;
  __fps_thd_stacksizes = threads->stacksizes;
  names = (const char **) malloc(getpagesize());

  pthread_key_create(&thread_cleanup_key, thread_cleanup_handler);
}

// NHM-NOTE: This doesn't need a lock b/c all callers have locked stuff.
size_t getUnusedIndex() {
  size_t i;
  for (i = 0; i < getVecSize(); ++i)
    if (!__fps_thd_stackptrs[i])
      return i;
  for (Thread *thread = threads; thread; thread = thread->next)
    thread->grow();
  map_length *= 2;
  FPS_CHECK(i < getVecSize());
  names = (const char **) realloc(names, map_length); // NHM-FIXME: Check.
  return i;
}

extern "C" __attribute__((visibility("default"))) uint64_t __fps_regstack(const char *name) {
  init_main_thread();

  Lock threads_lock(threads_mutex);
  
  const size_t index = getUnusedIndex();
  const size_t stacksize = kDefaultFPSSize;
  const size_t guardsize = getpagesize(); // NHM-FIXME
  FPS_LOG("registering %s (%" PRIu64 ")", name, index);
  names[index] = name;
  for (Thread *thread = threads; thread; thread = thread->next)
    thread->allocateStack(index, stacksize, guardsize);
  return index * sizeof(void *); // NHM-FIXME
}

extern "C" __attribute__((visibility("default"))) void __fps_deregstack(uint64_t index, const char *name) {
  Lock threads_lock(threads_mutex);
  
  index /= sizeof(void *); // NHM-FIXME: This should be moved into FPS's generated consturctor/destructor code, instead.
  for (Thread *thread = threads; thread; thread = thread->next)
    thread->deallocateStack(index);
  FPS_LOG("deregistered %s (%" PRIu64 ")", name, index);
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
  Thread *thread = thd_info->thread;
  __fps_thread = thread;
  __fps_thread->tid = safestack::GetTid();
  __fps_thd_stackptrs = thread->stackptrs;
  __fps_thd_stackbases = thread->stackbases;
  __fps_thd_stacksizes = thread->stacksizes;
  FPS_CHECK(__fps_thd_stackptrs && __fps_thd_stackbases && __fps_thd_stacksizes);
  pthread_setspecific(thread_cleanup_key, (void *) 1);
  return thd_info->start_routine(thd_info->arg);
}

void thread_cleanup_handler(void *_iter) {
  Lock threads_lock(threads_mutex);
  pthread_setspecific(thread_cleanup_key, nullptr);

  // Free stacks for dead threads.
  for (Thread **threadpp = &threads; *threadpp; ) {
    Thread *thread = *threadpp; 
    assert(thread->pid >= 0);
    assert(__fps_thread->pid >= 0);
    if (thread->pid != __fps_thread->pid || thread->tid >= 0 && thread->tid != __fps_thread->tid && safestack::TgKill(thread->pid, thread->tid, 0) < 0 && errno == ESRCH) {
      // NHM-FIXME: Unmap stacks.
      thread->~Thread();
      *threadpp = thread->next;
      free(thread);
    } else {
      threadpp = &thread->next;
    }
  }
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

  Lock threads_lock(threads_mutex);

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

  threads_lock.unlock();

  return ___interceptor_pthread_create(thread, attr, thread_start, thd_info);
}

struct GlobalContext {
  size_t num_stackptrs;
  void **stackptrs;
};

extern "C" __attribute__((visibility("default"))) GlobalContext *__fps_ctx_save() {
  GlobalContext *ctx = (GlobalContext *) malloc(sizeof(GlobalContext));
  ctx->num_stackptrs = getVecSize();
  ctx->stackptrs = (void **) malloc(sizeof(void *) * ctx->num_stackptrs);
  memcpy(ctx->stackptrs, __fps_thd_stackptrs, map_length);
  return ctx;
}

extern "C" __attribute__((visibility("default"))) void __fps_ctx_restore(GlobalContext *ctx) {
  memcpy(__fps_thd_stackptrs, ctx->stackptrs, ctx->num_stackptrs * sizeof(ctx->stackptrs[0]));
  free(ctx->stackptrs);
  free(ctx);
}

extern "C" __attribute__((visibility("default"))) int __fps_ctx_save_or_restore(GlobalContext **ctx, int setjmp_retval) {
  if (setjmp_retval)
    __fps_ctx_restore(*ctx);
  else
    *ctx = __fps_ctx_save();
  return setjmp_retval;
}

}
}
