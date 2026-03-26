add_compiler_rt_component(lockbox)

set(LOCKBOX_SOURCES
  lockbox.cpp
)

set(LOCKBOX_CFLAGS ${SANITIZER_COMMON_FLAGS})

foreach(arch ${LOCKBOX_SUPPORTED_ARCH})
  add_compiler_rt_runtime(clang_rt.lockbox
    STATIC
    ARCHS ${arch}
    SOURCES ${LOCKBOX_SOURCES}
    CFLAGS ${LOCKBOX_CFLAGS} -O0 -g # NHM-TODO: Remove these extra flags.
    PARENT_TARGET lockbox)
endforeach()
