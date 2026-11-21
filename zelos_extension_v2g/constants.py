"""Shared constants: trace naming and which names are usable."""

from collections.abc import Collection

import zelos_sdk

#: Default trace source (`advanced.prefix`).
DEFAULT_PREFIX = "V2G"

#: The extension's logs land at `<prefix>/log`, so no capture may be named `log`.
RESERVED_NAMES = ("log",)

#: Kernel-side capture buffer.
BUFFER_SIZE = 8 * 1024 * 1024


def name_error(
    value: str, label: str, reserved: Collection[str] = (), *, required: bool = False
) -> str | None:
    """Why user-typed `value` is not a legal trace name, or None if it is.

    Names become trace path segments, so a separator (`/ . @ :`) would silently
    re-nest the tree. Anything the SDK sanitizer rewrites is rejected, not renamed.
    Empty is legal (the caller's default applies) unless `required`.
    """
    if not value:
        return f"Invalid {label}: it must not be empty." if required else None
    if value in reserved:
        return f"Invalid {label} {value!r}: reserved for the extension's own logs."
    clean = zelos_sdk.sanitize_name(value, kind="source")
    if clean == value:
        return None
    offender = next((c for c, ok in zip(value, clean, strict=False) if c != ok), value[-1])
    return (
        f"Invalid {label} {value!r}: {offender!r} is not allowed. "
        "Use letters, digits, space, '_' or '-'."
    )
