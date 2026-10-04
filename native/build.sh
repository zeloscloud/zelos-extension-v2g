#!/usr/bin/env bash
# Build the libcbv2g-backed EXI decode shim into a self-contained shared library
# for the CURRENT platform, written to zelos_extension_v2g/exi/_lib/.
#
# This is a DEVELOPER/CI step, run once per target platform. The produced artifact
# is committed so end users never compile anything at install time (the agent's
# `uv sync` only installs pure-Python deps). See native/README.md.
set -euo pipefail

LIBCBV2G_URL="https://github.com/EVerest/libcbv2g"
# v0.3.2: the commit the committed exi/_lib artifacts were built from. Override with a
# tag or commit; bump LICENSE-libcbv2g's version line with it.
LIBCBV2G_REF="${LIBCBV2G_REF:-03350be048b35b179905129005a97144a4bdcf93}"

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$HERE/../zelos_extension_v2g/exi/_lib"
WORK="$HERE/.build"
mkdir -p "$WORK" "$OUT_DIR"

# 1. Fetch + build libcbv2g (Apache-2.0) static libraries.
# Fetch by ref so a commit pins as well as a tag; a stale checkout is replaced.
if [ "$(git -C "$WORK/libcbv2g" rev-parse HEAD 2>/dev/null)" != "$LIBCBV2G_REF" ]; then
    rm -rf "$WORK/libcbv2g"
    git init -q "$WORK/libcbv2g"
    git -C "$WORK/libcbv2g" fetch -q --depth 1 "$LIBCBV2G_URL" "$LIBCBV2G_REF"
    git -C "$WORK/libcbv2g" checkout -q FETCH_HEAD
fi
# -DCMAKE_POSITION_INDEPENDENT_CODE=ON is required: we link these static libs into a
# shared object, and on x86_64 non-PIC static code fails with "relocation R_X86_64_32S
# against `.rodata' can not be used when making a shared object" (arm64/macOS tolerate it).
cmake -S "$WORK/libcbv2g" -B "$WORK/libcbv2g/build" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON >/dev/null
cmake --build "$WORK/libcbv2g/build" -j >/dev/null

# 2. Platform-tagged artifact name (must match exi/libv2g.py).
sys=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$sys" in darwin) ext=dylib ;; *) sys=linux; ext=so ;; esac
arch=$(uname -m); case "$arch" in aarch64) arch=arm64 ;; esac
out="$OUT_DIR/libv2gshim-${sys}-${arch}.${ext}"

# 3. Compile the shim and statically link libcbv2g into one self-contained shared lib.
# din.a covers DIN 70121 + the supportedAppProtocol handshake (appHand lives there);
# iso2.a adds the ISO 15118-2 decoder; exi_codec.a is the shared bitstream core.
lib="$WORK/libcbv2g/build/lib/cbv2g"
cc -shared -fPIC "$HERE/v2g_din_shim.c" -I"$WORK/libcbv2g/include" \
    "$lib/libcbv2g_din.a" "$lib/libcbv2g_iso2.a" "$lib/libcbv2g_exi_codec.a" -lm -o "$out"

echo "built $out"
