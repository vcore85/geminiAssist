cmake_minimum_required(VERSION 3.18)
project(pcli_jni LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(PCLI_SRC_DIR "" CACHE PATH "Path to prism-client source directory (empty = stub mode)")

add_library(pcli_jni SHARED pcli_jni.cpp)

if(PCLI_SRC_DIR AND EXISTS "${PCLI_SRC_DIR}/CMakeLists.txt")
  message(STATUS "pcli_jni: full mode using prism-client at ${PCLI_SRC_DIR}")

  set(PCLI_BUILD_LIB_ONLY ON CACHE BOOL "Build only pcli_core library" FORCE)
  set(PCLI_ENABLE_CLASH_API ON CACHE BOOL "Enable Clash REST API" FORCE)
  set(PCLI_ENABLE_HY2MESH ON CACHE BOOL "Enable HY2Mesh outbound" FORCE)
  set(PCLI_BUILD_RELAY OFF CACHE BOOL "Disable pcli-relay" FORCE)
  set(PCLI_BUILD_HY2D OFF CACHE BOOL "Disable pcli-hy2d" FORCE)
  set(PCLI_BUILD_HY2M_BENCH OFF CACHE BOOL "Disable hy2m bench" FORCE)
  set(PCLI_BUILD_HY2M_TESTS OFF CACHE BOOL "Disable hy2m tests" FORCE)

  add_subdirectory("${PCLI_SRC_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/prism-client" EXCLUDE_FROM_ALL)

  if(ANDROID AND NOT PCLI_STATIC_ZLIB)
    find_library(ANDROID_Z_LIB z REQUIRED)
    target_compile_definitions(pcli_core PRIVATE PCLI_HAVE_ZLIB=1)
    target_link_libraries(pcli_core PUBLIC ${ANDROID_Z_LIB})
  endif()

  target_include_directories(pcli_jni PRIVATE "${PCLI_SRC_DIR}/include")
  pcli_apply_protocol_defs(pcli_jni)
  target_link_libraries(pcli_jni PRIVATE
    -Wl,--whole-archive pcli_core -Wl,--no-whole-archive
  )
else()
  message(WARNING "pcli_jni: PCLI_SRC_DIR not set or missing CMakeLists.txt; building in STUB mode")
  target_compile_definitions(pcli_jni PRIVATE PCLI_ANDROID_STUB=1)
endif()

if(ANDROID)
  find_library(ANDROID_LOG_LIB log REQUIRED)
  target_link_libraries(pcli_jni PRIVATE ${ANDROID_LOG_LIB})
else()
  find_package(JNI REQUIRED)
  target_include_directories(pcli_jni PRIVATE ${JNI_INCLUDE_DIRS})
  find_package(Threads REQUIRED)
  target_link_libraries(pcli_jni PRIVATE Threads::Threads)
endif()

if(NOT MSVC)
  target_compile_options(pcli_jni PRIVATE -Wall -Wextra)
  target_link_options(pcli_jni PRIVATE -Wl,--gc-sections)
endif()
