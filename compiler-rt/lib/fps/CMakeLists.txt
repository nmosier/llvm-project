add_compiler_rt_component(fps)

set(FPS_SOURCES
  fps.cpp
)

include_directories(..) # TODO: Not sure if this is needed.

set(FPS_CFLAGS ${SANITIZER_COMMON_CFLAGS})

foreach(arch ${FPS_SUPPORTED_ARCH})
  add_compiler_rt_runtime(clang_rt.fps
    STATIC
    ARCHS ${arch}
    SOURCES ${FPS_SOURCES}
            $<TARGET_OBJECTS:RTInterception.${arch}> # TODO: Not sure if this is needed
    CFLAGS ${FPS_CFLAGS}
    PARENT_TARGET fps)
endforeach()
