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

using ThreadID = safestack::ThreadId;

void thread_cleanup_handler(void *_iter);
void garbage_collect_threads(void);

/// Default size of function-private stacks.
const unsigned kDefaultFPSSize = 0x100000;
const unsigned kGuardSize = getpagesize();
const unsigned kStackAlign = 16;

// NHM-FIXME: MAke a static variable of Livethread?
size_t map_length = 0;

size_t getVecSize() {
  return map_length / sizeof(void *);
}

extern "C" __attribute__((visibility("default"))) thread_local void **__fps_thd_stackptrs = nullptr;
extern "C" __attribute__((visibility("default"))) thread_local void **__fps_thd_stackbases = nullptr;
extern "C" __attribute__((visibility("default"))) thread_local uint64_t *__fps_thd_stacksizes = nullptr;
const char **names = nullptr;
// TODO: add global, realloc'ed array of bools to determine if index is active.





class LiveThread {
public:
  // NHM-TODO: MAke private?
  void **&stackptrs;
  void **&stackbases;
  uintptr_t *&stacksizes;
  LiveThread *next = nullptr;

  LiveThread():
      stackptrs(__fps_thd_stackptrs),
      stackbases(__fps_thd_stackbases),
      stacksizes(__fps_thd_stacksizes)
  {
    stackptrs = CreateNewMap<void *>();
    stackbases = CreateNewMap<void *>();
    stacksizes = CreateNewMap<uintptr_t>();
  }

  LiveThread(const LiveThread &) = delete;
  LiveThread &operator=(const LiveThread&) = delete;

  void grow() {
    growOne(stackptrs);
    growOne(stackbases);
    growOne(stacksizes);
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
    assert(index < getVecSize());
    assert(stacksizes[index]);
    assert(stackbases[index]);
    safestack::Munmap(stackbases[index], stacksizes[index]);
    stacksizes[index] = 0;
    stackbases[index] = nullptr;
    stackptrs[index] = nullptr;
  }

private:
  static size_t CalculateMinSize(size_t num_stacks) {
    return align_up<size_t>(max<size_t>(1, num_stacks * sizeof(void *)), getpagesize());
  }

  template <typename T>
  static T *CreateNewMap() {
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
};




class DeadThread {
public:
  DeadThread() = delete;
  DeadThread(const DeadThread &) = delete;
  DeadThread &operator=(const DeadThread &) = delete;

  // NHM-tODO: Make some of these private.
  const size_t length;
  void ** const stackptrs;
  void ** const stackbases;
  uint64_t * const stacksizes;
  const pid_t pid;
  const ThreadID tid;
  DeadThread *next = nullptr;

  explicit DeadThread(const LiveThread &live_thread):
      length(map_length),
      stackptrs(live_thread.stackptrs),
      stackbases(live_thread.stackbases),
      stacksizes(live_thread.stacksizes),
      pid(getpid()),
      tid(safestack::GetTid())
  {
  }

  ~DeadThread() {
    assert(!(pid == getpid() && tid == safestack::GetTid()));

    // Unmap stacks.
    const size_t num_stacks = length / sizeof(uintptr_t);
    for (size_t i = 0; i < num_stacks; ++i) {
      if (stacksizes[i] == 0)
        continue;
      assert(stackbases[i]);
      safestack::Munmap(stackbases[i], stacksizes[i]); // NHM-tODO CHECK RET
    }

    // Unmap fields.
    safestack::Munmap(stackptrs, length);
    safestack::Munmap(stackbases, length);
    safestack::Munmap(stacksizes, length);
  }
  
private:
};


LiveThread *live_threads = nullptr;
DeadThread *dead_threads = nullptr;

pthread_mutex_t live_threads_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t dead_threads_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_key_t thread_cleanup_key;
thread_local LiveThread *__fps_thread = nullptr;

__attribute__((constructor(0))) void init_main_thread() {
  Lock live_threads_lock(live_threads_mutex);
  if (live_threads)
    return;
  
  map_length = getpagesize(); // NHM-FIXME: Maybe hard-code it instead?
  __fps_thread = live_threads = new (malloc(sizeof(LiveThread))) LiveThread();
  names = (const char **) malloc(getpagesize());

  pthread_key_create(&thread_cleanup_key, thread_cleanup_handler);

#if 0
  int rv;
  pthread_mutexattr_t mutexattr;
  rv = pthread_mutexattr_init(&mutexattr);
  FPS_CHECK(rv >= 0);
  rv = pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_ERRORCHECK);
  FPS_CHECK(rv >= 0);
  rv = pthread_mutex_init(&live_threads_mutex, &mutexattr);
  FPS_CHECK(rv >= 0);
  rv = pthread_mutex_init(&dead_threads_mutex, &mutexattr);
  FPS_CHECK(rv >= 0);
#endif
}

// NHM-NOTE: This doesn't need a lock b/c all callers have locked stuff.
size_t getUnusedIndex() {
  garbage_collect_threads();
  size_t i;
  for (i = 0; i < getVecSize(); ++i)
    if (!__fps_thd_stackptrs[i])
      return i;
  
  // NHM-FIXME: grow updates the thread-local buffer pointers, but we're calling this for all threads.
  // Definitely a bug. 
  for (LiveThread *thread = live_threads; thread; thread = thread->next)
    thread->grow();
  map_length *= 2;
  FPS_CHECK(i < getVecSize());
  names = (const char **) realloc(names, map_length); // NHM-FIXME: Check.
  return i;
}

extern "C" __attribute__((visibility("default"))) uint64_t __fps_regstack(const char *name) {
  init_main_thread();

  Lock live_threads_lock(live_threads_mutex);
  
  const size_t index = getUnusedIndex();
  const size_t stacksize = kDefaultFPSSize;
  const size_t guardsize = getpagesize(); // NHM-FIXME
  FPS_LOG("registering %s (%" PRIu64 ")", name, index);
  names[index] = name;
  for (LiveThread *thread = live_threads; thread; thread = thread->next)
    thread->allocateStack(index, stacksize, guardsize);
  return index * sizeof(void *); // NHM-FIXME
}

extern "C" __attribute__((visibility("default"))) void __fps_deregstack(uint64_t index, const char *name) {
  Lock live_threads_lock(live_threads_mutex);
  
  index /= sizeof(void *); // NHM-FIXME: This should be moved into FPS's generated consturctor/destructor code, instead.
  for (LiveThread *thread = live_threads; thread; thread = thread->next)
    thread->deallocateStack(index);
  FPS_LOG("deregistered %s (%" PRIu64 ")", name, index);
}

// NHM-TODO: Will need to add thread specific info here, like stack size, etc.
struct tinfo {
  void *(*start_routine)(void *);
  void *arg;
};

void *thread_start(void *arg) {
  Lock live_thread_lock(live_threads_mutex);
  
  tinfo *info = (tinfo *) arg;

  // Create a new thread.
  size_t size = kDefaultFPSSize;
  size_t guard = getpagesize(); // NHM-FIXME

  LiveThread *ref_thread = live_threads;
  assert(__fps_thread == nullptr);
  __fps_thread = new (malloc(sizeof(LiveThread))) LiveThread();
  __fps_thread->next = ref_thread;
  live_threads = __fps_thread;
  for (size_t i = 0; i < getVecSize(); ++i)
    if (ref_thread->stacksizes[i])
      __fps_thread->allocateStack(i, size, guard);

  pthread_setspecific(thread_cleanup_key, (void *) 1);

  live_thread_lock.unlock();
  
  return info->start_routine(info->arg);
}

// NOTE: Must have locked.
void garbage_collect_threads(void) {
  Lock dead_threads_lock(dead_threads_mutex);
  for (DeadThread **threadpp = &dead_threads; *threadpp; ) {
    DeadThread *thread = *threadpp;
    assert(thread);
    // NHM-FIXME: hoist getpid
    if (thread->pid != getpid() || (safestack::TgKill(thread->pid, thread->tid, 0) < 0 && errno == ESRCH)) {
      thread->~DeadThread();
      *threadpp = thread->next;
      free(thread);
    } else {
      threadpp = &thread->next;
    }
  }
}

void thread_cleanup_handler(void *_iter) {
  Lock live_threads_lock(live_threads_mutex);

  assert(__fps_thread);

  // Add this thread to the dead list.
  {
    Lock dead_threads_lock(dead_threads_mutex);
    DeadThread *dead_thread = new (malloc(sizeof(DeadThread))) DeadThread(*__fps_thread);
    dead_thread->next = dead_threads;
    dead_threads = dead_thread;
  }
  
  // Remove this thread from the live list and destroy it.
  LiveThread **live_thread = &live_threads;
  while (*live_thread != __fps_thread) {
    live_thread = &(*live_thread)->next;
    assert(live_thread); // since we expect to find the thread in the list somewhere
  }
  *live_thread = (*live_thread)->next;
  __fps_thread->~LiveThread();
  free(__fps_thread);
  __fps_thread = nullptr;

  // NHM-FIXME
  pthread_setspecific(thread_cleanup_key, nullptr);
  garbage_collect_threads();
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

  tinfo *info = (tinfo *) malloc(sizeof(tinfo));
  info->arg = arg;
  info->start_routine = start_routine;

  return ___interceptor_pthread_create(thread, attr, thread_start, info);
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
