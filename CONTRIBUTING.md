# Contributing

## Prerequisites

- [Zelos](https://zeloscloud.io) 26.0.10 or later
- [Zelos CLI](https://docs.zeloscloud.io/getting-started/install-cli/) 0.1.12 or later
- [just](https://github.com/casey/just)
- [uv](https://docs.astral.sh/uv/)

## Layout

`extension.toml` describes everything the extension contributes:

| Part | Files | Manifest |
| ---- | ----- | -------- |
| Agent runtime | `main.py`, the Python package, `pyproject.toml`, `config.schema.json` | `[agent]`, `[config]` |

| Path | Purpose |
| ---- | ------- |
| `main.py` | Entry point: app mode, and the `interfaces`, `check`, `capture`, `replay` and `convert` commands |
| `zelos_extension_v2g/` | Configuration, capture lifecycle, actions and CLI |
| `zelos_extension_v2g/demo/` | The bundled demo capture |
| `tests/files/` | A TLS session capture and its key log |

## Commands

| Command                | Description                                   |
| ---------------------- | --------------------------------------------- |
| `just install`         | Install dependencies and the pre-commit hooks |
| `just format`          | Format code with ruff                         |
| `just check`           | Check formatting and lint (ruff)              |
| `just test`            | Run tests (pytest)                            |
| `just package`         | Package for the Zelos marketplace             |
| `just release VERSION` | Bump version, check, test, commit, tag        |
| `just clean`           | Remove build output, caches and packages      |
| `just run`             | Run the extension against `./config.json`     |
| `just demo`            | Replay the bundled demo capture once          |
| `just interfaces`      | List capturable NICs                          |
| `just check-permissions` | Probe capture rights and print the fix      |

`just --list` also shows the other recipes. `just install` installs the pre-commit hooks in
`.pre-commit-config.yaml`.

## The decoder

Capture and V2G decode are `zelos-packet`'s. This extension builds the keyword arguments
(`zelos_extension_v2g/decode.py`) and decides where rows land
(`trace_layout` in `zelos_extension_v2g/capture.py`). Tests stub that seam, and run the
installed wheel over the bundled captures; decode correctness is tested with the decoder.

## Configuration

`config.schema.json` drives the configuration UI in the Zelos desktop app; `config.json` is
the shipped default. The interface picker uses a `ui:widget` hint rather than an enum,
because a static schema cannot enumerate a machine's NICs.

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

The release workflow checks, tests and packages the extension, then attaches the archive to a
GitHub release. CI runs the same check, test and package steps on every push and pull request.

To list the extension in the Zelos marketplace, once: push the project to a GitHub repository,
submit it at [marketplace.zeloscloud.io](https://marketplace.zeloscloud.io/), and install the
Zelos GitHub App on the repository when asked. After approval, every release you publish reaches
the marketplace. See
[Publish to the Marketplace](https://docs.zeloscloud.io/sdk/how-to/package-extensions/#publish-to-the-marketplace).
