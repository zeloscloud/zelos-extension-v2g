"""ISO 15118 / DIN 70121 V2G (EV-charger) communication decode and pcap-to-trace conversion."""

#: Action namespace for both the live registration (`zelos_sdk.init(name=...)`) and
#: the at-rest inventory dumped from `main.py`, which re-exports it. Nothing binds
#: the two, so a mismatch ships the actions under two unrelated paths.
ACTION_PREFIX = "V2G"

__all__ = ["ACTION_PREFIX"]
