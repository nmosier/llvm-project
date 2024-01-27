#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <sys/resource.h>
#include "safestack/safestack_util.h"
#include "safestack/safestack_platform.h"
#include "fps/fps_util.h"

// NHM-FIXME: Memory leak occurs when we resize arrays, methinks.

// NHM-FIXME: fps -> __fps.
namespace fps {

namespace {

void *placeholder = (void *) 0xdeadbeef; // NHM-FIXME: add real placeholder

using ThreadID = safestack::ThreadId;

void thread_cleanup_handler(void *_iter);
void garbage_collect_threads(void);

/// Default size of function-private stacks.
const unsigned kDefaultFPSSize = 0x2800000;

// NHM-FIXME: MAke a static variable of Livethread?
size_t map_length = 0;

size_t getVecSize();

// NHM-FIXME: Make it illegal to copy this.
struct fps_t {
  void *stackptr;
  void *stackbase;
  uintptr_t stacksize;

  fps_t(): stackptr(placeholder), stackbase(nullptr), stacksize(0) {}

  operator bool() const {
    FPS_CHECK((stackbase && stacksize) ||
              (!stackbase && !stacksize));
    return stackbase != nullptr;
  }

  bool allocated() const {
    return static_cast<bool>(*this);
  }

  void allocate(uintptr_t stacksize, uintptr_t guardsize) {
    FPS_CHECK(!allocated());
    stackbase = Mmap(nullptr, stacksize + guardsize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON);
    Mprotect((char *) stackbase, guardsize, PROT_NONE); // NHM-FIXME: need upper guard.
    this->stacksize = stacksize + guardsize; // NHM-FIXME: Rename argument.
    stackptr = (char *) stackbase + stacksize;
    FPS_CHECK(allocated());
  }

  void deallocate() {
    FPS_CHECK(allocated());
    if (safestack::Munmap(stackbase, stacksize) < 0)
      FPS_CHECK(false);
    stackbase = nullptr;
    stackptr = placeholder;
    stacksize = 0;
    FPS_CHECK(!allocated());
  }

  ~fps_t() {
    if (allocated())
      deallocate();
  }

  void resetStackPointer() {
    stackptr = (char *) stackbase + stacksize;
  }

  void setStackPointer(void *sp) {
    if (!allocated()) {
      FPS_CHECK(sp == placeholder);
      FPS_CHECK(stackptr == placeholder);
    } else if (sp == placeholder) {
      resetStackPointer();
    } else {
      FPS_CHECK(stackbase <= sp && sp <= (char *) stackbase + stacksize);
      stackptr = sp;
    }
  }
};
static_assert(sizeof(fps_t) == sizeof(void *) * 3, ""); // NHM-FIXME

extern "C" __attribute__((visibility("default"))) thread_local fps_t *__fps_thd_stacks = nullptr;
char *registered = nullptr;



size_t getVecSize() {
  return map_length / sizeof(fps_t);
}


class LiveThread {
public:
  // NHM-TODO: MAke private?
  fps_t *&stacks;
  const size_t default_stack_size;
  const size_t default_guard_size;
  // NHM-FIXME: Add a new array, name it "stackend" or "stacktop"
  LiveThread *next = nullptr;

  LiveThread(size_t default_stack_size, size_t default_guard_size):
      stacks(__fps_thd_stacks),
      default_stack_size(default_stack_size),
      default_guard_size(default_guard_size)
  {
    stacks = CreateNewMap<fps_t>();
  }

  LiveThread(const LiveThread &) = delete;
  LiveThread &operator=(const LiveThread&) = delete;

  void grow() {
    // NHM-FIXME: No longer need this intermediate thing.
    growOne(stacks);
  }

  void registerStack(size_t index) {
    FPS_CHECK(index < getVecSize());
    FPS_CHECK(!stacks[index]);
  }

  void allocateStack(size_t index) {
    FPS_CHECK(index < getVecSize());
    stacks[index].allocate(default_stack_size, default_guard_size);
  }

  void deallocateStack(size_t index) {
    FPS_CHECK(index < getVecSize());
    if (stacks[index])
      stacks[index].deallocate();
  }

private:
  template <typename T>
  static T *CreateNewMap() {
    T *map = (T *) Mmap(nullptr, map_length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON);
    for (size_t i = 0; i < map_length / sizeof(T); ++i)
      new (&map[i]) T();
    return map;
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

    for (size_t i = map_length / sizeof(T); i < map_length * 2 / sizeof(T); ++i) {
      new (&map[i]) T();
    }
  }  
};




class DeadThread {
public:
  DeadThread() = delete;
  DeadThread(const DeadThread &) = delete;
  DeadThread &operator=(const DeadThread &) = delete;

  // NHM-tODO: Make some of these private.
  const size_t length;
  fps_t * const stacks;
  const pid_t pid;
  const ThreadID tid;
  DeadThread *next = nullptr;

  explicit DeadThread(const LiveThread &live_thread):
      length(map_length),
      stacks(live_thread.stacks),
      pid(getpid()),
      tid(safestack::GetTid())
  {
  }

  ~DeadThread() {
    FPS_CHECK(!(pid == getpid() && tid == safestack::GetTid()));

    // Unmap stacks.
    const size_t num_stacks = length / sizeof(fps_t);
    for (size_t i = 0; i < num_stacks; ++i) {
      stacks[i].~fps_t();
    }

    // Unmap fields.
    if (safestack::Munmap(stacks, length) < 0)
      FPS_CHECK(false);
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

  // NHM-FIXME: Invert getVecSize() and map_length.
  registered = (decltype(registered)) calloc(getVecSize(), sizeof *registered);
  FPS_CHECK(registered);

  size_t stack_size = kDefaultFPSSize;
  size_t guard_size = 4096;
  struct rlimit limit;
  if (getrlimit(RLIMIT_STACK, &limit) == 0 && limit.rlim_cur != RLIM_INFINITY)
    stack_size = limit.rlim_cur;
  
  __fps_thread = live_threads = new (malloc(sizeof(LiveThread))) LiveThread(stack_size, guard_size);

  // Setup the thread cleanup handler.
  if (pthread_key_create(&thread_cleanup_key, thread_cleanup_handler) < 0)
    FPS_CHECK(false); // NHM-FIXME: FPS_ERR()
}

// NHM-NOTE: This doesn't need a lock b/c all callers have locked stuff.
// NHM-FIXME: Update name to reflect we're also allocating it.
// like 'claimUnusedIndex'
size_t getUnusedIndex() {
  garbage_collect_threads();
  size_t i;
  for (i = 0; i < getVecSize(); ++i)
    if (!registered[i])
      return i;

  FPS_LOG("growing maps %" PRIu64 " -> %" PRIu64, map_length, map_length * 2);
  for (LiveThread *thread = live_threads; thread; thread = thread->next)
    thread->grow();
  size_t old_vec_size = getVecSize();
  map_length *= 2;
  registered = (decltype(registered)) reallocarray(registered, getVecSize(), sizeof *registered);
  FPS_CHECK(registered);
  memset(registered + old_vec_size, 0, (getVecSize() - old_vec_size) * sizeof *registered);
  FPS_CHECK(i < getVecSize());
  FPS_CHECK(!registered[i]);
  return i;
}

extern "C" __attribute__((visibility("default"))) uint64_t __fps_regstack(const char *name) {
  init_main_thread();

  Lock live_threads_lock(live_threads_mutex);
  
  const size_t index = getUnusedIndex();
  registered[index] = true;
  FPS_LOG("registering %s (%" PRIu64 ")", name, index);
  for (LiveThread *thread = live_threads; thread; thread = thread->next)
    thread->registerStack(index);
  return index * sizeof(fps_t);
}

struct reginfo {
  uint64_t &index;
  const char *name;
  const uintptr_t &private_frame_size;
  void *&dummy_frame;
};
extern "C" __attribute__((visibility("default"))) void __fps_regstacks(uint64_t n, const reginfo *vec) {
  for (uint64_t i = 0; i < n; ++i) {
    auto &info = vec[i];
    info.index = __fps_regstack(info.name);
    FPS_CHECK(info.private_frame_size > 0);
    info.dummy_frame = malloc(info.private_frame_size);
    FPS_CHECK(info.dummy_frame);
  }
}

extern "C" __attribute__((visibility("default"))) void __fps_deregstack(uint64_t index, const char *name) {
  Lock live_threads_lock(live_threads_mutex);

  index /= sizeof(fps_t); // NHM-FIXME: This should be moved into FPS's generated constructor/destructor code, instead.
  
  for (LiveThread *thread = live_threads; thread; thread = thread->next)
    thread->deallocateStack(index);
  FPS_LOG("deregistered %s (%" PRIu64 ")", name, index);
}

extern "C" __attribute__((visibility("default"))) void __fps_deregstacks(uint64_t n, const reginfo *vec) {
  for (uint64_t i = 0; i < n; ++i) {
    auto &info = vec[i];
    __fps_deregstack(info.index, info.name);
    FPS_CHECK(info.dummy_frame);
    free(info.dummy_frame);
    info.dummy_frame = nullptr;
    info.index = -1;
  }
}

extern "C" __attribute__((visibility("default"))) void __fps_allocstack(uint64_t index) {
  index /= sizeof(fps_t);
  FPS_LOG("allocstack %" PRIu64, index);
  FPS_CHECK(!__fps_thd_stacks[index] && "allocstack called twice!");
  __fps_thread->allocateStack(index);
  FPS_CHECK(__fps_thd_stacks[index] && "allocstack failed!");
}

// NHM-TODO: Will need to add thread specific info here, like stack size, etc.
struct tinfo {
  void *(*start_routine)(void *);
  void *arg;
  size_t stack_size;
  size_t guard_size;
};

void *thread_start(void *arg) {
  Lock live_thread_lock(live_threads_mutex);
  
  tinfo *info = (tinfo *) arg;

  // Create a new thread.
  LiveThread *ref_thread = live_threads;
  FPS_CHECK(__fps_thread == nullptr);
  __fps_thread = new (malloc(sizeof(LiveThread))) LiveThread(info->stack_size, info->guard_size);
  __fps_thread->next = ref_thread;
  live_threads = __fps_thread;
#if 0
  for (size_t i = 0; i < getVecSize(); ++i)
    if (ref_thread->stacksizes[i])
      __fps_thread->allocateStack(i);
#endif

  pthread_setspecific(thread_cleanup_key, (void *) 1);

  live_thread_lock.unlock();
  
  return info->start_routine(info->arg);
}

// NOTE: Must have locked.
void garbage_collect_threads(void) {
  Lock dead_threads_lock(dead_threads_mutex);
  for (DeadThread **threadpp = &dead_threads; *threadpp; ) {
    DeadThread *thread = *threadpp;
    FPS_CHECK(thread);
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

  FPS_CHECK(__fps_thread);

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
    FPS_CHECK(live_thread); // since we expect to find the thread in the list somewhere
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

  if (attr) {
    pthread_attr_getstacksize(attr, &info->stack_size);
    pthread_attr_getguardsize(attr, &info->guard_size);
  } else {
    // get pthread default stack size
    pthread_attr_t tmpattr;
    pthread_attr_init(&tmpattr);
    pthread_attr_getstacksize(&tmpattr, &info->stack_size);
    pthread_attr_getguardsize(&tmpattr, &info->guard_size);
    pthread_attr_destroy(&tmpattr);
  }

  FPS_CHECK(info->stack_size);

  return ___interceptor_pthread_create(thread, attr, thread_start, info);
}

struct fps_ctx_t {
  size_t num_stackptrs;
  void **stackptrs;
  fps_ctx_t *next;
};

thread_local fps_ctx_t *ctx_top = nullptr;


// NHM-FIXME: Need mutexes!
extern "C" __attribute__((visibility("default"))) fps_ctx_t *__fps_ctx_push(fps_ctx_t *ctx) {
  if (ctx)
    return ctx;

  FPS_LOG("pushing context");

  // Calculate how much memory we need.
  ctx = (fps_ctx_t *) malloc(sizeof(fps_ctx_t));
  FPS_CHECK(ctx);
  ctx->num_stackptrs = getVecSize();
  ctx->stackptrs = (void **) malloc(ctx->num_stackptrs * sizeof(void *));
  FPS_CHECK(ctx->stackptrs);
  for (size_t i = 0; i < ctx->num_stackptrs; ++i) {
    ctx->stackptrs[i] = __fps_thd_stacks[i].stackptr;
    FPS_CHECK(ctx->stackptrs[i] != nullptr);
  }
  ctx->next = nullptr;

  // Append to the stack.
  fps_ctx_t **nextp;
  for (nextp = &ctx_top; *nextp; nextp = &(**nextp).next) {}
  *nextp = ctx;

  return ctx;
}

extern "C" __attribute__((visibility("default"))) void __fps_ctx_pop(fps_ctx_t *ctx) {
  if (!ctx)
    return;

  FPS_LOG("popping context");
  
  FPS_CHECK(ctx->next == nullptr);
  fps_ctx_t **prevp;
  for (prevp = &ctx_top; *prevp != ctx; prevp = &(**prevp).next) {}
  free(ctx->stackptrs);
  free(ctx);
  *prevp = nullptr;
}

extern "C" __attribute__((visibility("default"))) void __fps_ctx_restore(fps_ctx_t *ctx) {
  FPS_LOG("restoring context");
  FPS_CHECK(ctx);
  FPS_CHECK(ctx->num_stackptrs <= getVecSize());
  size_t i;
  for (i = 0; i < ctx->num_stackptrs; ++i)
    __fps_thd_stacks[i].setStackPointer(ctx->stackptrs[i]);
  for (; i < getVecSize(); ++i)
    __fps_thd_stacks[i].resetStackPointer();

  // Erase rest of list (not including this context, since it might be re-used).
  for (fps_ctx_t *next = ctx->next; next; ) {
    fps_ctx_t *dead_ctx = next;
    next = dead_ctx->next;
    free(dead_ctx->stackptrs);
    free(dead_ctx);
  }
  ctx->next = nullptr;
}

extern "C" __attribute__((visibility("default"))) int __fps_ctx_push_or_restore(fps_ctx_t *&ctx, int setjmp_retval) {
  if (setjmp_retval) {
    __fps_ctx_restore(ctx);
  } else {
    ctx = __fps_ctx_push(ctx);
  }
  return setjmp_retval;
}

}
}
