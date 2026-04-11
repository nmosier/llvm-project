#include "sanitizer_common/sanitizer_allocator.h"
#include "sanitizer_common/sanitizer_common.h"

#include "lockbox.h"
#include <sys/mman.h>

using namespace __sanitizer;

namespace __lockbox {

namespace {

class LockboxMapUnmapCallback {
  void ProtectRange(uptr p, uptr size) const {
    int rv = pkey_mprotect(reinterpret_cast<void *>(p), size,
                           PROT_READ | PROT_WRITE, pkey);
    LOCKBOX_CHECK(rv >= 0);
    LOCKBOX_LOG(stderr, "ProtectRange(%p, %#lx)\n", p, size);
  }

public:
  // Fires for every primary-allocator commit (region info, free arrays,
  // metadata, user data). Allocator bookkeeping must remain accessible
  // without the pkey, so we deliberately do nothing here.
  void OnMap(uptr p, uptr size) const {}
  // Fires only for user-data commits in the primary allocator's regions.
  // This is where chunks served to __lockbox_malloc live, so pkey-protect it.
  void OnMapUser(uptr p, uptr size) const { ProtectRange(p, size); }
  void OnMapSecondary(uptr p, uptr size, uptr user_begin,
                      uptr user_size) const {
    ProtectRange(user_begin, user_size);
  }
  void OnUnmap(uptr p, uptr size) const {}
};

struct AP64 {
  static const uptr kSpaceBeg = ~(uptr)0;
  static const uptr kSpaceSize = 0x2000000000ULL; // 128G
  static const uptr kMetadataSize = 0;
  using SizeClassMap = DefaultSizeClassMap;
  using MapUnmapCallback = LockboxMapUnmapCallback;
  static const uptr kFlags = 0;
  using AddressSpaceView = LocalAddressSpaceView;
};

} // namespace

using PrimaryAllocator = SizeClassAllocator64<AP64>;
using Allocator = CombinedAllocator<PrimaryAllocator>;
using AllocatorCache = Allocator::AllocatorCache;

static Allocator allocator;

static AllocatorCache *GetAllocatorCache() {
  static thread_local AllocatorCache cache;
  static thread_local bool initialized = false;
  if (UNLIKELY(!initialized)) {
    allocator.InitCache(&cache);
    initialized = true;
  }
  return &cache;
}

void InitAllocator() { allocator.Init(/*release_to_os_interval_ms=*/-1); }

} // namespace __lockbox

extern "C" {

void *__lockbox_malloc(size_t size) {
  return __lockbox::allocator.Allocate(__lockbox::GetAllocatorCache(), size,
                                       /*alignment=*/8);
}

void __lockbox_free(void *ptr) {
  __lockbox::allocator.Deallocate(__lockbox::GetAllocatorCache(), ptr);
}

}
