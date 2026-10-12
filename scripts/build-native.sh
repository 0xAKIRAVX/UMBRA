#!/bin/bash
# build-native.sh — builds the Rust core (libumbra_core.so) for every Android
# ABI + the host (Robolectric test) variant, linking the C JNI shim.
#
# Usage: scripts/build-native.sh [release|debug]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CORE="$ROOT/native/umbra-core"
NDK="${ANDROID_NDK_HOME:-/home/z/android-sdk/ndk/27.2.12479018}"
LLVM="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
API=26
OUT="$ROOT/app/src/main/jniLibs"
HOST_OUT="$ROOT/app/src/test/resources/native"
MODE="${1:-release}"

export RUSTUP_HOME="${RUSTUP_HOME:-/home/z/.rustup}"
export CARGO_HOME="${CARGO_HOME:-/home/z/.cargo}"
export PATH="$CARGO_HOME/bin:$PATH"

CARGO_FLAGS=""
if [ "$MODE" = "release" ]; then
  CARGO_FLAGS="--release"
  TARGET_DIR="release"
else
  TARGET_DIR="debug"
fi

mkdir -p "$OUT/arm64-v8a" "$OUT/armeabi-v7a" "$OUT/x86_64" "$HOST_OUT"

build_android() {
  local rust_target=$1 jni_dir=$2 clang=$3
  echo "== rust: $rust_target =="
  (cd "$CORE" && cargo build $CARGO_FLAGS --target "$rust_target")
  echo "== link: $clang =="
  "$LLVM/$clang" -shared -fPIC -O2 -o "$OUT/$jni_dir/libumbra_core.so" \
    "$CORE/jni/shim.c" \
    "$CORE/target/$rust_target/$TARGET_DIR/libumbra_core.a" \
    -lm -ldl
  echo "   -> $OUT/$jni_dir/libumbra_core.so"
}

build_android aarch64-linux-android arm64-v8a aarch64-linux-android${API}-clang
build_android armv7-linux-androideabi armeabi-v7a armv7a-linux-androideabi${API}-clang
build_android x86_64-linux-android x86_64 x86_64-linux-android${API}-clang

# host build (x86_64-unknown-linux-gnu) for Robolectric in-process tests
echo "== rust: x86_64-unknown-linux-gnu (host) =="
(cd "$CORE" && cargo build $CARGO_FLAGS --target x86_64-unknown-linux-gnu)
echo "== link: host cc =="
JAVA_INC="${JAVA_HOME:-/home/z/tools/jdk-17.0.20.1+1}/include"
# NOTE: the host artifact carries a .so.bin extension because AGP filters
# plain .so files out of unit-test java resources; the bridge renames it to
# a temp .so at load time.
cc -shared -fPIC -O2 -o "$HOST_OUT/umbra_core_host.so.bin" \
  -I"$JAVA_INC" -I"$JAVA_INC/linux" \
  "$CORE/jni/shim.c" \
  "$CORE/target/x86_64-unknown-linux-gnu/$TARGET_DIR/libumbra_core.a" \
  -lm -lpthread -ldl
echo "   -> $HOST_OUT/umbra_core_host.so.bin"

echo "ALL NATIVE BUILDS DONE"
ls -la "$OUT"/*/*.so "$HOST_OUT"/*.so.bin
