#!/usr/bin/env bash
# Builds dist/WINAGENT.EXE for Windows 95 on Linux (Ubuntu: apt-get install gcc-mingw-w64-i686).
# Usage: ./build.sh            -> build + checks
# Env:   WINAGENT_BUILD        -> version text shown in the chat (default: git describe)
#        WINAGENT_MODEL        -> default model in the start window (default: mistralai/mistral-nemo)
#        WINAGENT_FALLBACK_IP  -> IP of openrouter.ai used when the PC has no DNS (default: none)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD="$ROOT/build"
DIST="$ROOT/dist"
CC=i686-w64-mingw32-gcc
BEARSSL_URL=https://www.bearssl.org/bearssl-0.6.tar.gz
BEARSSL_SHA256=6705bba1714961b41a728dfc5debbe348d2966c117649392f8c8139efc83ff14
VERSION="${WINAGENT_BUILD:-$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)}"
MODEL="${WINAGENT_MODEL:-mistralai/mistral-nemo}"

command -v $CC >/dev/null || { echo "$CC not found: apt-get install gcc-mingw-w64-i686" >&2; exit 1; }
mkdir -p "$BUILD" "$DIST"

# 1. BearSSL (TLS 1.2 in plain C, no allocation, no OS dependencies)
if [ ! -f "$BUILD/bearssl/libbearssl.a" ]; then
  curl -sSfL -o "$BUILD/bearssl.tar.gz" "$BEARSSL_URL"
  echo "$BEARSSL_SHA256  $BUILD/bearssl.tar.gz" | sha256sum -c --quiet
  rm -rf "$BUILD/bearssl" && mkdir -p "$BUILD/bearssl" && tar xzf "$BUILD/bearssl.tar.gz" -C "$BUILD/bearssl" --strip-components=1
  # Windows 95 does not save SSE registers and has no crypto RNG: plain i586 code, seed comes from WinAgent
  (cd "$BUILD/bearssl" && for f in $(find src -name '*.c'); do
    $CC -c -Os -march=i586 -mno-sse -mno-mmx -fno-stack-protector -ffunction-sections -fdata-sections \
      -DBR_AES_X86NI=0 -DBR_SSE2=0 -DBR_RDRAND=0 -DBR_USE_URANDOM=0 -DBR_USE_WIN32_RAND=0 \
      -DBR_USE_UNIX_TIME=0 -DBR_USE_WIN32_TIME=0 -Iinc -Isrc "$f" -o "${f%.c}.o" &
  done; wait; i686-w64-mingw32-ar rcs libbearssl.a $(find src -name '*.o'))
fi

# 2. WinAgent: no C runtime, only kernel32, user32, gdi32 and wsock32, PE marked for Windows 4.0
DEFS=(-DOR_BUILD="\"$VERSION\"" -DOR_MODEL="\"$MODEL\"")
[ -n "${WINAGENT_FALLBACK_IP:-}" ] && DEFS+=(-DOR_FALLBACK_IP="\"$WINAGENT_FALLBACK_IP\"")
$CC -Os -march=i586 -mno-sse -mno-mmx -fno-stack-protector -fno-tree-loop-distribute-patterns \
  -ffunction-sections -fdata-sections -nostdlib -mwindows -e _WinMainCRTStartup \
  -Wl,--subsystem,windows:4.0 -Wl,--major-os-version,4 -Wl,--minor-os-version,0 -Wl,--gc-sections -s \
  -Wl,--disable-dynamicbase,--disable-nxcompat,--disable-reloc-section,--file-alignment,4096 \
  "${DEFS[@]}" -I"$ROOT/src" -I"$BUILD/bearssl/inc" "$ROOT/src/winagent.c" "$BUILD/bearssl/libbearssl.a" \
  -lkernel32 -luser32 -lgdi32 -lwsock32 -lgcc -o "$DIST/WINAGENT.EXE"

# 3. Checks: Windows 4.0 subsystem, only the four Win95 DLLs, no SSE/MMX instructions
EXE="$DIST/WINAGENT.EXE"
HDR="$(i686-w64-mingw32-objdump -p "$EXE")"
grep -q 'MajorSubsystemVersion.*4' <<<"$HDR" || { echo "FAIL: subsystem version is not 4" >&2; exit 1; }
DLLS="$(grep 'DLL Name' <<<"$HDR" | awk '{print toupper($3)}' | sort | tr '\n' ' ')"
[ "$DLLS" = "GDI32.DLL KERNEL32.DLL USER32.DLL WSOCK32.DLL " ] || { echo "FAIL: unexpected imports: $DLLS" >&2; exit 1; }
SIMD="$(i686-w64-mingw32-objdump -d "$EXE" | grep -c -E 'xmm|%mm[0-7]' || true)"
[ "$SIMD" = 0 ] || { echo "FAIL: $SIMD SSE/MMX instructions" >&2; exit 1; }

(cd "$DIST" && sha256sum WINAGENT.EXE > WINAGENT.EXE.sha256)
echo "OK $VERSION: $(wc -c <"$EXE") bytes, imports $DLLS"
cat "$DIST/WINAGENT.EXE.sha256"
