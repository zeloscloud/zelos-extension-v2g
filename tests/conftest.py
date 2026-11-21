"""Shared fixtures: a stand-in `zelos_packet`, so the wiring is exercised
without a socket or an agent.

Decode correctness is not tested here; it lives with the decoder in zelos-packet.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from zelos_extension_v2g import pkg

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "config.schema.json"
FILES = REPO_ROOT / "tests" / "files"


class InterfaceNotFoundError(ValueError):
    """Named as `zelos_packet.InterfaceNotFoundError`."""


class FakeMetrics(SimpleNamespace):
    v2g_tls_decrypted = 0  # the attribute `decode.supported()` probes for


class FakeCapture:
    """Records the kwargs it was constructed with; never touches a socket.

    The real ``PacketCapture`` signature, spelled out rather than
    ``**kwargs``, so a keyword drifting out of `capture_kwargs()` fails here.
    """

    instances: list[FakeCapture] = []
    is_active = True
    error = None

    def __init__(
        self,
        interface,
        snaplen=0,
        promiscuous=False,
        buffer_bytes=2 * 1024 * 1024,
        exclude_outgoing=False,
        source_name="Packet",
        log_frames=True,
        stored_frame_bytes=256,
        stats_interval=1.0,
        exclude_agent_addrs=None,
        exclude_agent_port=None,
        source=None,
        name=None,
        agent_url=None,
        someip_sd_port=None,
        someip_ports=None,
        doip_port=None,
        arxml=None,
        goose=False,
        scl=None,
        filter=None,
        v2g=False,
        tls_keylog=None,
    ):
        self.kwargs = {k: v for k, v in locals().items() if k != "self"}
        self.started = self.stopped = False
        FakeCapture.instances.append(self)

    def start(self) -> None:
        if self.kwargs["interface"] == "nope0":
            raise InterfaceNotFoundError("network interface 'nope0' not found")
        self.started = True

    def stop(self) -> None:
        self.stopped = True

    def stats(self) -> SimpleNamespace:
        return SimpleNamespace(
            packets_read=12, bytes_read=1024, packets_truncated=0, kernel_drops=0,
            decode_stall_ms=0.0, read_errors=0,
        )  # fmt: skip

    def metrics(self) -> FakeMetrics:
        return FakeMetrics(v2g_messages=8, v2g_decoded=8, v2g_tls_connections=1)


class FakeDecoder:
    """The real ``PacketDecoder`` signature, spelled out for the same reason."""

    instances: list[FakeDecoder] = []
    metrics = FakeCapture.metrics

    def __init__(
        self,
        name="capture",
        source_name="Packet",
        iface=None,
        log_frames=True,
        stored_frame_bytes=256,
        emit_schemas_on_init=False,
        source=None,
        exclude_agent_addrs=None,
        exclude_agent_port=None,
        someip_sd_port=None,
        someip_ports=None,
        doip_port=None,
        arxml=None,
        signal_source=None,
        pdu_source=None,
        goose=False,
        scl=None,
        goose_source=None,
        v2g=False,
        tls_keylog=None,
    ):
        self.kwargs = {k: v for k, v in locals().items() if k != "self"}
        self.flushed = False
        self.realtime = self.path = None
        FakeDecoder.instances.append(self)

    def convert_file(self, path: str, *, realtime: bool = False) -> int:
        self.realtime, self.path = realtime, path
        return 155

    def flush(self) -> None:
        self.flushed = True


class FakeTraceSource:
    def __init__(self, source_name, namespace=None, *, cached: bool = True) -> None:
        self.name = source_name
        self.namespace = namespace
        self.cached = cached


FAKE_REMEDIATION = "fake native remediation: do the thing"


def make_fake_module() -> SimpleNamespace:
    return SimpleNamespace(
        PacketCapture=FakeCapture,
        PacketDecoder=FakeDecoder,
        Metrics=FakeMetrics,
        list_interfaces=lambda: [
            SimpleNamespace(name="lo0", is_up=True, is_loopback=True, addresses=["127.0.0.1"]),
            SimpleNamespace(name="en0", is_up=True, is_loopback=False, addresses=["10.0.0.5"]),
        ],
        capture_supported=lambda: True,
        permission_remediation=lambda: FAKE_REMEDIATION,
        sanitize_name=lambda raw: (
            __import__("re").sub(r"[.:@/\s]+", "_", raw.strip()).strip("_") or "capture"
        ),
    )


@pytest.fixture
def fake_packet(monkeypatch) -> SimpleNamespace:
    """A stand-in `zelos_packet` (and trace source) for one test."""
    from zelos_extension_v2g import capture as capture_mod

    FakeCapture.instances.clear()
    FakeDecoder.instances.clear()
    module = make_fake_module()
    monkeypatch.setattr(pkg, "module", lambda: module)
    monkeypatch.setattr(pkg, "available", lambda: True)
    monkeypatch.setattr(capture_mod, "make_trace_source", FakeTraceSource)
    return module
