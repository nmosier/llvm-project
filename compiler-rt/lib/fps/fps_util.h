#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "safestack/safestack_platform.h"

#define FPS_DEBUG_ABORT 0

#ifdef FPS_DEBUG_ABORT
#define FPS_ABORT()                             \
  do {                                          \
    fprintf(stderr, "[fps] FATAL ERROR: attach to pid %d to debug\n", getpid()); \
    volatile int x = 1;                                                 \
    while (x) {}                                                        \
  } while (false)
#else
#define FPS_ABORT() abort()
#endif

#define FPS_CHECK(a)                                            \
  do {                                                          \
    if (!(a)) {                                                 \
      fprintf(stderr, "fps CHECK failed: %s:%d %s\n", __FILE__, \
              __LINE__, #a);                                    \
      FPS_ABORT();                                              \
    }                                                           \
  } while (false)

#define FPS_LOGGING 0
#if FPS_LOGGING
# define FPS_LOG(...)                            \
  do {                                          \
    fprintf(stderr, "[fps] ");                  \
    fprintf(stderr, __VA_ARGS__);               \
    fprintf(stderr, "\n");                      \
  } while (false)
#else
# define FPS_LOG(...) do {} while (false)
#endif

inline void *operator new(size_t count, void *here) { return here; }

namespace fps {

template <typename T>
T max(T a, T b) {
  return a > b ? a : b;
}

template <typename T>
T align_up(T n, T align) {
  return ((n + (align - 1)) / align) * align;
}

inline void *Mremap(void *old_address, size_t old_size, size_t new_size, int flags = 0, void *new_address = nullptr) {
  void *map;
#if SANITIZER_NETBSD
  map = __mremap(old_address, old_size, new_size, flags, new_address);
#elif SANITIZER_FREEBSD && (defined(__aarch64__) || defined(__x86_64__))
  map = (void *) __syscall(SYS_mremap, old_address, old_size, new_size, flags, new_address);
#else
  map = (void *) syscall(SYS_mremap, old_address, old_size, new_size, flags, new_address);
#endif
  return map;
}

inline void *Mmap(void *addr, size_t length, int prot, int flags, int fd = -1, off_t offset = 0) {
  void *map = safestack::Mmap(addr, length, prot, flags, fd, offset);
  if (map == MAP_FAILED) {
    perror("[fps] mmap failed");
    abort();
  }
  return map;
}

inline void Mprotect(void *addr, size_t length, int prot) {
  int rv = safestack::Mprotect(addr, length, prot);
  if (rv < 0) {
    perror("[fps] mprotect");
    abort();
  }
}

#if 0
template <typename T>
class PinnedVector {
  static size_t calculateMinSize(size_t init_size) {
    return max<size_t>(getpagesize(), align_up<size_t>(init_size * sizeof(T), getpagesize()));
  }
public:
#if 0
  PinnedVector(): size(0), map_length(getpagesize()),
                  data(static_cast<T *>(safestack::Mmap(nullptr, map_length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0))) {
    FPS_CHECK(data);
  }
#endif

  PinnedVector(size_t init_size):
      size(init_size), map_length(calculateMinSize(init_size)),
      data(static_cast<T *>(safestack::Mmap(nullptr, map_length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0))) {
    FPS_CHECK(data != MAP_FAILED);
    for (size_t i = 0; i < size; ++i) {
      new (&data[i]) T();
      assert(data[i]);
    }
  }

  size_t insert(T &&x) {
    T *item = get_unused();
    *item = static_cast<T &&>(x);
    return item - data;
  }

  T *getData() const {
    return data;
  }

  T &operator[](size_t index) {
    assert(index < size);
    return data[index];
  }

private:
  size_t size;
  size_t map_length;
  T * const data;


  void grow() {
    // Extend mapping by one page.
    const size_t new_map_length = map_length + getpagesize();
    void *new_data = Mremap(data, map_length, new_map_length, 0);
    FPS_CHECK(new_data == data);
    map_length = new_map_length;
  }

  T *get_unused() {
    // Try to allocate an already-constructed but invalidated entry.
    for (size_t i = 0; i < size; ++i) {
      T *x = &data[i];
      if (!*x)
        return x;
    }

    // Grow the map if necessary.
    while ((size + 1) * sizeof(T) > map_length)
      grow();

    // Construct a new entry.
    T *x = &data[size++];
    new (x) T();
    return x;
  }
};
#endif

class Lock {
  pthread_mutex_t *mutex;
  bool locked;

public:
  Lock(pthread_mutex_t &mutex): mutex(&mutex), locked(false) {
    lock();
  }
  
  ~Lock() {
    if (locked)
      unlock();
  }

  void lock() {
    assert(!locked);
    pthread_mutex_lock(mutex);
    locked = true;
  }

  void unlock() {
    assert(locked);
    pthread_mutex_unlock(mutex);
    locked = false;
  }
};

}

