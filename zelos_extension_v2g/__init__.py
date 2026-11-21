"""Zelos V2G extension.

ISO 15118 / DIN 70121 charging links, live or from a capture file. Capture and
decode are the Rust-cored `zelos-packet` package's; this package is the
configuration, the actions and the CLI around it.
"""

from . import _agent_env  # noqa: F401  (first: sets the environment before anything reads it)

#: The namespace actions are addressed under. One definition for the live
#: registration (`zelos_sdk.init(name=ACTION_PREFIX, actions=True)`) and the
#: at-rest inventory the packaging step dumps from `main.py`, which re-exports it.
ACTION_PREFIX = "V2G"

__all__ = ["ACTION_PREFIX"]
