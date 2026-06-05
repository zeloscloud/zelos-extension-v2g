#!/usr/bin/env bash
# Cross-build the Linux EXI-decode shims (x86_64 + arm64) from any host with Docker,
# by running native/build.sh inside manylinux2014 containers. manylinux2014 has a
# glibc-2.17 baseline, so the resulting .so loads on essentially any Linux from the
# last decade. Artifacts land in zelos_extension_v2g/exi/_lib/ and are committed.
#
# Usage:  bash native/build-linux.sh            # both arches
#         ARCHES="x86_64" bash native/build-linux.sh   # just one
#
# Requires a running Docker daemon. The non-native arch builds under QEMU emulation
# (slower). See native/README.md.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
ARCHES="${ARCHES:-x86_64 arm64}"

declare -A PLATFORM=( [x86_64]=linux/amd64 [arm64]=linux/arm64 )
declare -A IMAGE=(
    [x86_64]=quay.io/pypa/manylinux2014_x86_64
    [arm64]=quay.io/pypa/manylinux2014_aarch64
)

for arch in $ARCHES; do
    echo ">>> building linux/$arch via ${IMAGE[$arch]}"
    # An anonymous volume masks the host's native/.build scratch dir so the container
    # clones + builds libcbv2g fresh for its own architecture.
    docker run --rm --platform "${PLATFORM[$arch]}" \
        -v "$REPO":/work -v /work/native/.build -w /work \
        "${IMAGE[$arch]}" \
        bash -lc 'bash native/build.sh'
done

echo "done. Linux shims:"
ls -1 "$REPO"/zelos_extension_v2g/exi/_lib/*.so
