#!/usr/bin/env bash
set -euo pipefail

# Build libpcli_jni.so for Android ABIs using Android NDK + CMake + Ninja.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CPP_DIR="${ROOT_DIR}/app/src/main/cpp"
JNILIBS_DIR="${ROOT_DIR}/app/src/main/jniLibs"
BUILD_ROOT="${ROOT_DIR}/build/native"

ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-/home/ln/Android/Sdk/ndk/26.3.11579264}}"
if [[ ! -d "${ANDROID_NDK_HOME}" ]]; then
  echo "ERROR: ANDROID_NDK_HOME does not exist: ${ANDROID_NDK_HOME}" >&2
  exit 1
fi

TOOLCHAIN_FILE="${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake"
ABIS="${ABIS:-arm64-v8a}"
ANDROID_PLATFORM="${ANDROID_PLATFORM:-android-26}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
PCLI_SRC_DIR="${PCLI_SRC_DIR:-/home/ln/pcli-android/.build-deps/prism-client}"
OPENSSL_ROOT_DIR="${OPENSSL_ROOT_DIR:-/home/ln/pcli-android/.build-deps/openssl}"
PCLI_STATIC_OPENSSL="${PCLI_STATIC_OPENSSL:-OFF}"
PCLI_STATIC_ZLIB="${PCLI_STATIC_ZLIB:-OFF}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

for ABI in ${ABIS}; do
  echo "==> Building libpcli_jni.so for ${ABI} (${BUILD_TYPE}, ${ANDROID_PLATFORM})"
  ABI_BUILD_DIR="${BUILD_ROOT}/${ABI}"

  CMAKE_ARGS=(
    -S "${CPP_DIR}"
    -B "${ABI_BUILD_DIR}"
    -G Ninja
    -DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN_FILE}"
    -DANDROID_ABI="${ABI}"
    -DANDROID_PLATFORM="${ANDROID_PLATFORM}"
    -DANDROID_STL=c++_static
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}"
    -DPCLI_STATIC_OPENSSL="${PCLI_STATIC_OPENSSL}"
    -DPCLI_STATIC_ZLIB="${PCLI_STATIC_ZLIB}"
  )

  if [[ -n "${PCLI_SRC_DIR}" && -d "${PCLI_SRC_DIR}" ]]; then
    CMAKE_ARGS+=(-DPCLI_SRC_DIR="${PCLI_SRC_DIR}")
  fi

  if [[ -n "${OPENSSL_ROOT_DIR}" ]]; then
    if [[ -d "${OPENSSL_ROOT_DIR}/${ABI}" ]]; then
      OPENSSL_PREFIX="${OPENSSL_ROOT_DIR}/${ABI}"
    else
      OPENSSL_PREFIX="${OPENSSL_ROOT_DIR}"
    fi
    CMAKE_ARGS+=(-DOPENSSL_ROOT_DIR="${OPENSSL_PREFIX}" -DPCLI_OPENSSL_ROOT="${OPENSSL_PREFIX}")
    if [[ -f "${OPENSSL_PREFIX}/lib/libssl.a" && -f "${OPENSSL_PREFIX}/lib/libcrypto.a" ]]; then
      CMAKE_ARGS+=(
        -DOPENSSL_INCLUDE_DIR="${OPENSSL_PREFIX}/include"
        -DOPENSSL_SSL_LIBRARY="${OPENSSL_PREFIX}/lib/libssl.a"
        -DOPENSSL_CRYPTO_LIBRARY="${OPENSSL_PREFIX}/lib/libcrypto.a"
      )
    fi
  fi

  cmake "${CMAKE_ARGS[@]}"
  cmake --build "${ABI_BUILD_DIR}" --target pcli_jni -j "${JOBS}"

  mkdir -p "${JNILIBS_DIR}/${ABI}"
  cp -f "${ABI_BUILD_DIR}/libpcli_jni.so" "${JNILIBS_DIR}/${ABI}/libpcli_jni.so"
  echo "==> Installed ${JNILIBS_DIR}/${ABI}/libpcli_jni.so"
done
