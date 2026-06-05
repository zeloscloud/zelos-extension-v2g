# native/ — EXI decode shim (libcbv2g)

V2G application messages are EXI-encoded (schema-informed binary). Rather than
reimplement a schema-informed EXI codec in Python, we reuse EVerest's
[`libcbv2g`](https://github.com/EVerest/libcbv2g) (Apache-2.0), the reference
DIN 70121 / ISO 15118-2/-20 codec.

`v2g_din_shim.c` is a thin C function that decodes one DIN V2G message and emits a
compact JSON object of the telemetry-relevant fields. `build.sh` statically links it
against libcbv2g into a single self-contained shared library, written to
`../zelos_extension_v2g/exi/_lib/libv2gshim-<os>-<arch>.<ext>`.

## Why a prebuilt, bundled binary

The Zelos agent installs an extension by running `uv sync` **on the target machine**,
so a native dependency built from source would require a C toolchain + CMake on every
user's machine. Instead we **prebuild once per platform** and commit the artifact; the
extension's Python is pure (`ctypes` is stdlib), so install just works with no compiler
and no PyPI publishing. `zelos_extension_v2g/exi/libv2g.py` loads the matching artifact
and degrades gracefully (Layer-1 framing only) if none is present for the platform.

## Rebuilding

```bash
./native/build.sh                 # builds for the current platform
LIBCBV2G_REF=<tag> ./native/build.sh   # pin a libcbv2g release
```

Run on each platform Zelos targets (e.g. macOS arm64, Linux x86_64) and commit the
resulting `exi/_lib/*.{dylib,so}`. Requires `cmake`, a C compiler, and `git`.

The libcbv2g static libs are built with `-DCMAKE_POSITION_INDEPENDENT_CODE=ON`; this is
required on x86_64 (non-PIC static code can't be linked into a `.so` — it fails with
`relocation R_X86_64_32S … can not be used when making a shared object`) and harmless
elsewhere.

## Cross-building the Linux shims from any host

`build-linux.sh` runs `build.sh` inside **manylinux2014** containers (x86_64 + arm64),
so you can produce both Linux `.so`s from a macOS/Docker box without a Linux machine:

```bash
bash native/build-linux.sh              # both arches (non-native runs under QEMU)
ARCHES="x86_64" bash native/build-linux.sh
```

manylinux2014 has a glibc-2.17 baseline, so the artifacts load on essentially any Linux
from the last decade (the current shims need only GLIBC_2.2.5 on x86_64 / GLIBC_2.17 on
arm64). Committed artifacts: `darwin-arm64.dylib`, `linux-x86_64.so`, `linux-arm64.so`.
