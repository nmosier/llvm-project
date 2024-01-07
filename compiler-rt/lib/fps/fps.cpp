#include "interception/interception.h"
#include <stdio.h>
#include <stdint.h>
#include "safestack/safestack_util.h"

namespace {

/// Default size of function-private stacks.
const unsigned kDefaultFPSSize = 0x10000;

#if 0
// NHM-FIXME: Use size_t rather than uint64_t?
extern "C" __attribute__((visibility("default"))) void *__fps_alloc(uint64_t size, uint64_t guard) {
  size_t size = kDefaultFPSSize;
}

#endif

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

}
