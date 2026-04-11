#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdint.h>

#include "lockbox_arch.h"
#include "lockbox.h"

using namespace __lockbox;

namespace __lockbox {
namespace {

void enable_permissions(pkey_mask_t mask);
void disable_permissions(pkey_mask_t mask);

} // namespace
}

extern "C" {

bool __lockbox_enabled = false;
pkey_mask_t __lockbox_mask_enable;
pkey_mask_t __lockbox_mask_disable;

void __lockbox_access_enable(void) {
  enable_permissions(__lockbox_mask_enable);
}

void __lockbox_access_disable(void) {
  disable_permissions(__lockbox_mask_disable);
}

bool __lockbox_access_enabled(void) {
  const auto pkru = get_pkru();
  return pkru == pkey_mask_intersect(pkru, __lockbox_mask_enable);
}

}

namespace __lockbox {

int pkey = -1;

namespace {

void set_pkey(int new_pkey) {
  LOCKBOX_CHECK(pkey < 0);
  pkey = new_pkey;
  __lockbox_mask_enable = arch_pkey_enable_mask(pkey);
  __lockbox_mask_disable = ~__lockbox_mask_enable;
}

void reset_pkey(void) {
  LOCKBOX_CHECK(pkey >= 0);
  pkey_free(pkey);
  pkey = -1;
}

void enable_permissions(pkey_mask_t mask) {
  pkey_mask_t pkru = get_pkru();
  pkru = pkey_mask_union(pkru, mask);
  set_pkru(pkru);
}

void disable_permissions(pkey_mask_t mask) {
  pkey_mask_t pkru = get_pkru();
  pkru = pkey_mask_intersect(pkru, mask);
  set_pkru(pkru);
}

__attribute__((constructor(0))) void init(void) {
  __lockbox::InitAllocator();
  // Allocate a fresh key and disable access.
  const auto new_pkey = pkey_alloc(0, 0);
  set_pkey(new_pkey);
  disable_permissions(__lockbox_mask_disable);
  __lockbox_enabled = true;
}

__attribute__((destructor(0))) void deinit(void) {
  reset_pkey();
  __lockbox_enabled = false;
}

} // namespace

} // namespace __lockbox
