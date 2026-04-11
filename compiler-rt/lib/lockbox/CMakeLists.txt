include_directories(..)

add_compiler_rt_component(lockbox)

set(LOCKBOX_SOURCES
  lockbox.cpp
  lockbox_malloc.cpp
)

set(LOCKBOX_CFLAGS ${SANITIZER_COMMON_CFLAGS})

foreach(arch ${LOCKBOX_SUPPORTED_ARCH})
  add_compiler_rt_runtime(clang_rt.lockbox
    STATIC
    ARCHS ${arch}
    SOURCES ${LOCKBOX_SOURCES}
            $<TARGET_OBJECTS:RTSanitizerCommon.${arch}>
            $<TARGET_OBJECTS:RTSanitizerCommonLibc.${arch}>
    CFLAGS ${LOCKBOX_CFLAGS} -O0 -g # NHM-TODO: Remove these extra flags.
    PARENT_TARGET lockbox)
endforeach()
