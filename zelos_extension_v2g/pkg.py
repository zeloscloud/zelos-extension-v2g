"""Import probe for the Rust-cored ``zelos-packet`` package.

A missing native package is one legible line rather than a traceback, and
`module()` is the monkeypatch seam the tests use. Whether the installed package
can decode V2G at all is `decode.py`'s question.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_module: Any | None = None
_import_error: BaseException | None = None
_import_attempted = False


class PacketPackageUnavailable(RuntimeError):
    """`zelos-packet` is not importable in this interpreter."""


def _import() -> None:
    global _module, _import_error, _import_attempted
    if _import_attempted:
        return
    _import_attempted = True
    try:
        import zelos_packet
    except Exception as exc:  # ImportError, or a native-load failure
        _import_error = exc
        logger.debug("zelos-packet is not importable: %s", exc)
    else:
        _module = zelos_packet


def available() -> bool:
    """True when `zelos_packet` imported cleanly."""
    _import()
    return _module is not None


def skip_reason() -> str:
    """One-line explanation for why the package is unusable (for test skips)."""
    _import()
    if _module is not None:
        return ""
    return (
        f"zelos-packet is not installed or failed to load ({_import_error!r}). "
        "Install it with `uv sync`."
    )


def module() -> Any:
    """The imported `zelos_packet` module, or a legible error.

    Tests monkeypatch this function to inject a stand-in module, which is why
    every call site in this extension goes through it.
    """
    _import()
    if _module is None:
        raise PacketPackageUnavailable(skip_reason()) from _import_error
    return _module


def capture_supported() -> bool:
    """Whether live capture has a native backend here (Linux/macOS/Windows)."""
    return bool(module().capture_supported()) if available() else False


def permission_remediation() -> str:
    """The package's own capture-privilege instructions; empty when unavailable."""
    return str(module().permission_remediation()) if available() else ""


def sanitize_name(name: str) -> str | None:
    """The package's own capture-name rule, or `None` when it is unavailable."""
    if not available():
        return None
    fn = getattr(module(), "sanitize_name", None)
    return str(fn(name)) if fn is not None else None


def is_permission_error(exc: BaseException) -> bool:
    """`CapturePermissionError` subclasses `PermissionError`; a typo'd interface
    (`InterfaceNotFoundError`, a ValueError) correctly does not match."""
    return isinstance(exc, PermissionError)
