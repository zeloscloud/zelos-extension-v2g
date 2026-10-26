# Contributing

## Prerequisites

- [Zelos](https://zeloscloud.io) 26.0.10 or later
- [Zelos CLI](https://docs.zeloscloud.io/reference/cli/) 0.1.11 or later
- [just](https://github.com/casey/just)
- [uv](https://docs.astral.sh/uv/)

## Layout

`extension.toml` describes everything the extension contributes:

| Part | Files | Manifest |
| ---- | ----- | -------- |
| Agent runtime | `main.py`, the Python package, `pyproject.toml`, `config.schema.json` | `[agent]`, `[config]` |

| Path | Purpose |
| ---- | ------- |
| `main.py` | Entry point: agent mode, and the `convert`, `live` and `decode` commands |
| `zelos_extension_v2g/` | Capture decode, the trace codec and the actions |
| `zelos_extension_v2g/exi/_lib/` | The prebuilt EXI decode shim, one per platform |
| `native/` | The shim's C source and build scripts |
| `tests/files/` | Sample captures and the example CAN database |

## Commands

| Command                | Description                                        |
| ---------------------- | -------------------------------------------------- |
| `just install`         | Install dependencies and the pre-commit hooks      |
| `just format`          | Format code with ruff                              |
| `just check`           | Check formatting and lint (ruff)                   |
| `just test`            | Run tests (pytest)                                 |
| `just package`         | Package for the Zelos marketplace                  |
| `just release VERSION` | Bump version, check, test, commit, tag             |
| `just clean`           | Remove build output, caches and packages           |

`just --list` also shows the recipes each part adds. `just install` installs the
pre-commit hooks in `.pre-commit-config.yaml`.

The tests run on the captures in `tests/files/` and need no network interface. The EXI
field-decode tests skip on a platform with no shim in `zelos_extension_v2g/exi/_lib/`.

## Run it in Zelos

```bash
zelos extensions install-local .
zelos extensions start local.v2g
```

A local install runs from your project directory, so you do not install again after a code
change:

- Agent runtime: stop and start the extension. After a dependency change, stop it and run
  `zelos extensions reinstall local.v2g`.
- `extension.toml`: run `zelos extensions install-local .` again.

## Rebuild the EXI shim

```bash
bash native/build.sh          # the current platform
bash native/build-linux.sh    # both Linux shims, in manylinux containers
```

Commit the rebuilt files in `zelos_extension_v2g/exi/_lib/`. See
[`native/README.md`](native/README.md) for what each script needs.

## Packaging

```bash
just package
```

The archive lands next to `extension.toml` as `<name>-<version>.tar.gz`, where `<name>` is the
manifest name in lowercase with every other run of characters turned into one hyphen. It holds
`extension.toml`, the README, the icon, the config schema and the paths listed in
`[package] paths`. With an agent runtime it also holds `pyproject.toml`, `uv.lock` and
`actions.json`, the list of actions that run while the extension is stopped.

## Release

```bash
just release 1.0.0
git push --follow-tags
```

The release workflow checks, tests, builds and packages the extension, then attaches the
archive to a GitHub release.
