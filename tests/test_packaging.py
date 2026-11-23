"""`zelos extensions package` reads extension.toml and refuses on a dangling path.

Every miss below would surface for the first time at tag time, in the release
workflow, with the tag already pushed. Catching it in CI is the whole point.
"""

from __future__ import annotations

import tomllib

import pytest

from .conftest import REPO_ROOT

MANIFEST = tomllib.loads((REPO_ROOT / "extension.toml").read_text())


@pytest.mark.parametrize("relative", MANIFEST["package"]["paths"])
def test_package_path_exists(relative: str) -> None:
    assert (REPO_ROOT / relative).exists(), f"[package] paths names a missing {relative}"


@pytest.mark.parametrize("key", ["icon", "readme"])
def test_referenced_file_exists(key: str) -> None:
    assert (REPO_ROOT / MANIFEST[key]).is_file(), f"manifest {key} points at a missing file"


def test_config_schema_exists() -> None:
    assert (REPO_ROOT / MANIFEST["config"]["schema"]).is_file()


def test_entry_point_is_packaged() -> None:
    assert MANIFEST["agent"]["entry"] in MANIFEST["package"]["paths"]


def test_entry_module_re_exports_the_action_prefix() -> None:
    """At-rest and live actions must land in one namespace: the manifest name,
    which is also the default trace prefix, so a user types what they read."""
    import main
    from zelos_extension_v2g import ACTION_PREFIX
    from zelos_extension_v2g.constants import DEFAULT_PREFIX

    assert main.ACTION_PREFIX == ACTION_PREFIX == DEFAULT_PREFIX == MANIFEST["name"]


def test_packet_pin_is_exact_and_locked() -> None:
    """The capture helper and the decoder surface are matched to one release."""
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    [pin] = [d for d in pyproject["project"]["dependencies"] if d.startswith("zelos-packet")]
    lock = tomllib.loads((REPO_ROOT / "uv.lock").read_text())
    [locked] = [p["version"] for p in lock["package"] if p["name"] == "zelos-packet"]
    assert pin == f"zelos-packet=={locked}"


def test_versions_agree() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    assert pyproject["project"]["version"] == MANIFEST["version"]
