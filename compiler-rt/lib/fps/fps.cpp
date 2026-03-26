#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <sys/resource.h>
#include "safestack/safestack_util.h"
#include "safestack/safestack_platform.h"
#include "fps/fps_util.h"
#include "fps/fps_ll.h"

// ===== PROJECTS ===== //
// Resizeable, Pinned Stack Vectors: (OBSOLETE?)
//  - use memfd_create? Well this doesn't play nicely with fork(). We'd need to instrument that.
//  - two-level mapping should be enough.
//  - NOTE: I think the above is obsoleted by our linked-list approach.
//
// OPTIONS:
//  - disable exception/longjmp support. This means that the program should never execute a longjmp that
//    skips over a private stack frame. It looks like
//
// FIXING GLOBAL ARRAYS:
//  - we should actually make configs[] and stacks[] arrays that track their size. Maybe thru a global variable at first.
//
// CUSTOM ALLOCATION FUNCTIONS:
//  - Need to specify custom allocation functions.
//
// SUPPORT SINGLE-THREADED FPSes
//  - A function can be compiled as 'single-thread FPS'
//
// USE DISTRIBUTED TLS STORAGE:
//  - Just need to make sure to call __tls_get_addr() from within the FPS runtime before the function is ever called.
//
// NORECURSE:
// - For functions that will not recurse, then we can just have a single private stack frame, and we can avoid the linked list and just have a single pointer. This should be the common case, and it should be faster.
// 
// CONSTANT FRAME SIZES:
// - Right now, frame sizes are stored in read-only memory (.ro?). This means we have to do an additional load every time we want to add/sub; not good. 
//   Surely there's a way to embed the constants. We can probably do a look up during machine IR and replace with constant value.

// NHM-FIXME: Memory leak occurs when we resize arrays, methinks.

using namespace __fps; // NHM-FIXME: Shouldn't need this later on.

// NHM-FIXME: fps -> __fps.
namespace fps {

namespace {

using ThreadID = safestack::ThreadId;

void thread_cleanup_handler(void *_iter);
void garbage_collect_threads(void);

constexpr size_t kDefaultMaxPrivateStacks = 0x100000;
size_t gMaxPrivateStacks = kDefaultMaxPrivateStacks;
size_t gNumPrivateStacks = 0;

struct frame_t;

class frame_handle_t {
  frame_t *end;
public:
  frame_handle_t(): end(nullptr) {}

  operator bool() const {
    return end != nullptr;
  }

  frame_t &operator*();
  const frame_t &operator*() const;
  frame_t *operator->();
  const frame_t *operator->() const;
  frame_handle_t &operator=(frame_t *frame);
  operator frame_t*() const;

  bool operator==(const frame_handle_t &o) const {
    return end == o.end;
  }
};

// NHM-FIXME: Class-ify this.
struct frame_t {
  frame_handle_t prev;
  frame_handle_t next;
};

frame_t &frame_handle_t::operator*() {
  return end[-1];
}

const frame_t &frame_handle_t::operator*() const {
  return end[-1];
}

frame_t *frame_handle_t::operator->() {
  return end - 1;
}

const frame_t *frame_handle_t::operator->() const {
  return end - 1;
}

frame_handle_t &frame_handle_t::operator=(frame_t *frame) {
  end = frame + 1;
  return *this;
}

frame_handle_t::operator frame_t*() const {
  return end - 1;
}

struct fps_t {
  frame_handle_t current_frame;
  frame_t *top_frame; // NHM-FIXME: Don't need this necessarily.
  size_t private_frame_size;

  fps_t(): top_frame(nullptr), private_frame_size(0) {}
  fps_t(const fps_t &) = delete;
  fps_t &operator=(const fps_t &) = delete;

private:
  size_t getFrameAllocSize() const {
    return sizeof(fps_t) + private_frame_size;
  }

public:
  bool registered() const {
    FPS_CHECK((current_frame && top_frame && private_frame_size) ||
              (!current_frame && !top_frame && !private_frame_size));
    return current_frame;
  }

  void Register(size_t private_frame_size) {
    FPS_CHECK(!registered());

    this->private_frame_size = private_frame_size;

    current_frame = (frame_t *) malloc(getFrameAllocSize());
    FPS_CHECK(current_frame);
    current_frame->prev = current_frame;
    current_frame->next = current_frame;

    top_frame = current_frame;
  }

  void Deregister() {
    // Free frame linked list.
    for (frame_t *it = current_frame->prev; it != it->prev; ) {
      frame_t *prev = it->prev;
      memset(it, 0, getFrameAllocSize());
      free(it); // NHM-FIXME: Creat function free_and_zero. Actually frees should just always free.
      it = prev;
    }
    for (frame_t *it = current_frame->next; it != it->next; ) {
      frame_t *next = it->next;
      free(it);
      it = next;
    }
    free(current_frame);

    // Zero out variables to indicate deregistration.
    current_frame = nullptr;
    top_frame = nullptr;
    private_frame_size = 0;
  }

  ~fps_t() {
    if (registered())
      Deregister();
  }

  void resetToTopFrame() {
    current_frame = top_frame;
  }

  void setCurrentFrame(frame_t *frame) {
    if (!registered())
      return;
    if (frame)
      current_frame = frame;
    else
      current_frame = top_frame;
  }

  // NHM-FIXME: probably want to allocatem more than just one.
  void MoreStack() {
    FPS_CHECK(current_frame->next == current_frame);

    frame_t *new_frame = (frame_t *) malloc(private_frame_size + sizeof(frame_t));
    FPS_CHECK(new_frame);
    current_frame->next = new_frame;
    new_frame->prev = current_frame;
    new_frame->next = new_frame;
  }
};

extern "C" __attribute__((visibility("default"))) thread_local fps_t *__fps_thd_stacks = nullptr;


struct shared_config_t {
  bool registered; // Whether this index has been registered.
  unsigned private_frame_size;

  shared_config_t(): registered(false), private_frame_size(0) {}

  void Register(unsigned private_frame_size) {
    FPS_CHECK(!registered);
    registered = true;
    this->private_frame_size = private_frame_size;
  }

  void Deregister() {
    FPS_CHECK(registered);
    registered = false;
  }
  
};
shared_config_t *configs = nullptr;


class LiveThread {
public:
  // NHM-TODO: MAke private?
  fps_t *&stacks;
  const size_t num_private_stacks;
  LiveThread *next = nullptr;

  LiveThread(size_t num_private_stacks): stacks(__fps_thd_stacks), num_private_stacks(num_private_stacks)
  {
    // Allocate array of fps_t structs.
    // NHM-FIXME: Check for unsigned overflow.
    stacks = (fps_t *) Mmap(nullptr, num_private_stacks * sizeof(fps_t), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON);

    // Initialize array of fps_t structs.
    // NHM-FIXME: Should just create pinned vector here.
    for (size_t i = 0; i < num_private_stacks; ++i) {
      new (&stacks[i]) fps_t();
      if (configs[i].registered)
        stacks[i].Register(configs[i].private_frame_size);
    }
  }

  LiveThread(const LiveThread &) = delete;
  LiveThread &operator=(const LiveThread&) = delete;

  void registerStack(size_t index) {
    FPS_CHECK(index < num_private_stacks);
    FPS_CHECK(configs[index].registered);
    stacks[index].Register(configs[index].private_frame_size);
  }

  void deregisterStack(size_t index) {
    FPS_CHECK(index < gNumPrivateStacks);
    stacks[index].Deregister();
  }
};




class DeadThread {
public:
  DeadThread() = delete;
  DeadThread(const DeadThread &) = delete;
  DeadThread &operator=(const DeadThread &) = delete;

  // NHM-tODO: Make some of these private.
  const size_t num_stacks;
  fps_t * const stacks;
  const pid_t pid;
  const ThreadID tid;
  DeadThread *next = nullptr;

  explicit DeadThread(const LiveThread &live_thread):
      num_stacks(live_thread.num_private_stacks),
      stacks(live_thread.stacks),
      pid(getpid()),
      tid(safestack::GetTid())
  {
    live_thread.stacks = nullptr;
  }

  ~DeadThread() {
    FPS_CHECK(!(pid == getpid() && tid == safestack::GetTid()));

    // Unmap stacks.
    for (size_t i = 0; i < num_stacks; ++i)
      stacks[i].~fps_t();

    // Unmap fields.
    if (safestack::Munmap(stacks, num_stacks * sizeof(fps_t)) < 0) // NHM-FIXME: Integer overflow.
      FPS_CHECK(false); // NHM-FIXME
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

  if (const char *s = getenv("FPS_MAX")) {
    char *end;
    size_t max_private_stacks = strtoul(s, &end, 0);
    if (!*end && *s)
      gMaxPrivateStacks = max_private_stacks;
    else
      FPS_LOG("invalid number for FPS_MAX");
  }
  
  // NHM-FIXME: Invert getVecSize() and map_length.
  configs = (shared_config_t *) calloc(gMaxPrivateStacks, sizeof(shared_config_t));
  FPS_CHECK(configs);
  for (size_t i = 0; i < gMaxPrivateStacks; ++i)
    new (&configs[i]) shared_config_t();

#if 0
  // I wrote this 2 years ago, but I don't remember yet what I was aiming for.
  struct rlimit limit;
  if (getrlimit(RLIMIT_STACK, &limit) == 0 && limit.rlim_cur != RLIM_INFINITY)
    stack_size = limit.rlim_cur;
#endif
  
  __fps_thread = live_threads = new (malloc(sizeof(LiveThread))) LiveThread(gMaxPrivateStacks);

  // Setup the thread cleanup handler.
  if (pthread_key_create(&thread_cleanup_key, thread_cleanup_handler) < 0)
    FPS_CHECK(false); // NHM-FIXME: FPS_ERR()
}

// NHM-NOTE: This doesn't need a lock b/c all callers have locked stuff.
// NHM-FIXME: Update name to reflect we're also allocating it.
// like 'claimUnusedIndex'
size_t getUnusedIndex() {
  garbage_collect_threads();
  for (size_t i = 0; i < gNumPrivateStacks; ++i)
    if (!configs[i].registered)
      return i;

  if (gNumPrivateStacks < gMaxPrivateStacks) {
    FPS_CHECK(!configs[gNumPrivateStacks].registered);
    return gNumPrivateStacks++;
  }

  FPS_CHECK(false && "too many functions with private stacks! Increase the limit with [NHM-FIXME]");
  abort();
}

// NHM-FIXME: private_{stack->frame}_size
extern "C" __attribute__((visibility("default"))) uint64_t __fps_regstack(const char *name, unsigned private_stack_size) {
  init_main_thread();

  Lock live_threads_lock(live_threads_mutex);
  
  const size_t index = getUnusedIndex();
  configs[index].Register(private_stack_size);
  FPS_LOG("registering %s (%" PRIu64 ")", name, index);
  for (LiveThread *thread = live_threads; thread; thread = thread->next)
    thread->registerStack(index);
  return index * sizeof(fps_t);
}

struct reginfo {
  uint64_t &index;
  const char *name;
  const uintptr_t &private_frame_size;
};
extern "C" __attribute__((visibility("default"))) void __fps_regstacks(uint64_t n, const reginfo *vec) {
  for (uint64_t i = 0; i < n; ++i) {
    auto &info = vec[i];
    if (!info.private_frame_size)
      continue;
    info.index = __fps_regstack(info.name, info.private_frame_size);
  }
}

extern "C" __attribute__((visibility("default"))) void __fps_deregstack(uint64_t index, const char *name) {
  Lock live_threads_lock(live_threads_mutex);

  index /= sizeof(fps_t); // NHM-FIXME: This should be moved into FPS's generated constructor/destructor code, instead.
  
  for (LiveThread *thread = live_threads; thread; thread = thread->next)
    thread->deregisterStack(index);
  FPS_LOG("deregistered %s (%" PRIu64 ")", name, index);
}

extern "C" __attribute__((visibility("default"))) void __fps_deregstacks(uint64_t n, const reginfo *vec) {
  for (uint64_t i = 0; i < n; ++i) {
    auto &info = vec[i];
    if (!info.private_frame_size)
      continue;
    __fps_deregstack(info.index, info.name);
    info.index = -1;
  }
}

extern "C" __attribute__((visibility("default"))) void __fps_morestack(uint64_t index) {
  index /= sizeof(fps_t);
  __fps_thd_stacks[index].MoreStack();
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
  __fps_thread = new (malloc(sizeof(LiveThread))) LiveThread(gMaxPrivateStacks);
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

// NHM-FIXME: Rename appropriately.
struct fps_ctx_t {
  size_t num_stackptrs;
  frame_t **stackptrs;
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
  ctx->num_stackptrs = gNumPrivateStacks;
  ctx->stackptrs = (frame_t **) malloc(ctx->num_stackptrs * sizeof(frame_t *)); // NHM-FIXME: Check for overflow.
  FPS_CHECK(ctx->stackptrs);
  for (size_t i = 0; i < ctx->num_stackptrs; ++i)
    ctx->stackptrs[i] = __fps_thd_stacks[i].current_frame;
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
  FPS_CHECK(ctx->num_stackptrs <= gNumPrivateStacks);
  size_t i;
  for (i = 0; i < ctx->num_stackptrs; ++i)
    __fps_thd_stacks[i].setCurrentFrame(ctx->stackptrs[i]);
  for (; i < gNumPrivateStacks; ++i)
    __fps_thd_stacks[i].resetToTopFrame();

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
