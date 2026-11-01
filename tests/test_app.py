"""Agent mode applies its configuration. No running Zelos agent is needed."""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
import zelos_sdk
from scapy.error import Scapy_Exception

from zelos_extension_v2g.cli import app
from zelos_extension_v2g.extension import V2gConverter

FIXTURE = Path(__file__).parent / "files" / "2024-04-20_ModelY_pyPLC_stop_in_precharge.pcapng"


@pytest.fixture
def agent_mode(monkeypatch: pytest.MonkeyPatch):
    """Runs agent mode with a given config, offline, returning once it would idle."""
    root = logging.getLogger()
    level = root.level
    monkeypatch.setattr(root, "handlers", list(root.handlers))
    monkeypatch.setattr(zelos_sdk, "init", lambda *args, **kwargs: None)
    monkeypatch.setattr(zelos_sdk, "actions_registry", SimpleNamespace(register=lambda _obj: None))
    monkeypatch.setattr(app, "TraceLoggingHandler", lambda _name: logging.NullHandler())
    monkeypatch.setattr(app.signal, "signal", lambda *args: None)
    monkeypatch.setattr(V2gConverter, "run", lambda self: None)

    def run(config: dict) -> None:
        monkeypatch.setattr(app, "load_config", lambda: config)
        app.run_app_mode()

    yield run
    root.setLevel(level)


@pytest.mark.parametrize("level", ["DEBUG", "WARNING", "ERROR"])
def test_log_level_sets_the_root_logger(agent_mode, level: str) -> None:
    agent_mode({"log_level": level})
    assert logging.getLogger().level == getattr(logging, level)


def test_log_level_defaults_to_info(agent_mode) -> None:
    logging.getLogger().setLevel(logging.DEBUG)
    agent_mode({})
    assert logging.getLogger().level == logging.INFO


@pytest.mark.parametrize("config", [{}, {"replay_pcap": "capture.pcapng"}])
def test_logs_record_on_the_v2g_source(
    agent_mode, monkeypatch: pytest.MonkeyPatch, config: dict
) -> None:
    sources: list = []
    monkeypatch.setattr(
        app, "TraceLoggingHandler", lambda source: sources.append(source) or logging.NullHandler()
    )
    monkeypatch.setattr(app, "sniff_into", lambda *_args, **_kwargs: None)
    agent_mode({"source_name": "ev", **config})
    assert [getattr(s, "name", s) for s in sources] == ["ev"]


@pytest.mark.parametrize("run", ["run_live", "run_decode"])
def test_cli_logs_record_on_the_v2g_source(monkeypatch: pytest.MonkeyPatch, run: str) -> None:
    from zelos_extension_v2g import live

    sources: list = []
    codecs: list = []
    monkeypatch.setattr(logging.getLogger(), "handlers", list(logging.getLogger().handlers))
    monkeypatch.setattr(zelos_sdk, "init", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        live, "TraceLoggingHandler", lambda source: sources.append(source) or logging.NullHandler()
    )
    monkeypatch.setattr(live, "sniff_into", lambda codec, **_kwargs: codecs.append(codec))
    monkeypatch.setattr(live, "decode_stream_into", codecs.append)
    getattr(live, run)(source_name="ev")
    assert len(sources) == 1
    assert sources[0] is codecs[0].source


def test_saved_config_off_the_schema_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    saved = tmp_path / "config.json"
    saved.write_text(json.dumps({"log_level": "LOUD"}))
    monkeypatch.setenv("ZELOS_CONFIG_PATH", str(saved))
    monkeypatch.chdir(Path(__file__).parents[1])
    with pytest.raises(SystemExit) as exc:
        app.run_app_mode()
    assert exc.value.code == 1
    assert [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR] == [
        "Invalid configuration: log_level: 'LOUD' is not one of "
        "['DEBUG', 'INFO', 'WARNING', 'ERROR']"
    ]


def _converter(agent_mode, monkeypatch: pytest.MonkeyPatch, config: dict) -> V2gConverter:
    """The converter agent mode starts with `config`, once its live capture thread has ended."""
    converters: list[V2gConverter] = []
    monkeypatch.setattr(V2gConverter, "run", lambda self: converters.append(self))
    agent_mode(config)
    for thread in threading.enumerate():
        if thread.name == "v2g-live":
            thread.join(5)
    (converter,) = converters
    return converter


def test_get_status_runs_without_live_capture(agent_mode, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _converter(agent_mode, monkeypatch, {}).get_status() == {"running": True}


class NoPacketSocket:
    """Linux's packet socket without CAP_NET_RAW."""

    def __init__(self, *_args, **_kwargs) -> None:
        raise PermissionError(1, "Operation not permitted")


class NoBpfAccess:
    """scapy's BPF socket (macOS) when this user may not open /dev/bpf*: its `get_dev_bpf`
    turns the PermissionError into a Scapy_Exception."""

    def __init__(self, *_args, **_kwargs) -> None:
        try:
            raise PermissionError(13, "Permission denied", "/dev/bpf0")
        except OSError as e:
            raise Scapy_Exception(
                "Permission denied: could not open /dev/bpf0. "
                "Make sure to be running Scapy as root ! (sudo)"
            ) from e


class NoBpfDevice:
    """scapy's BPF socket when every /dev/bpf* is busy: not a permission error."""

    def __init__(self, *_args, **_kwargs) -> None:
        raise Scapy_Exception("No /dev/bpf handle is available !")


@pytest.mark.parametrize(
    ("socket", "error"),
    [
        (
            NoPacketSocket,
            "Live capture on {iface} needs raw-socket rights (CAP_NET_RAW): restart the Zelos "
            "agent as root, or with CAP_NET_RAW as an ambient capability, then start the extension "
            "again",
        ),
        (
            NoBpfAccess,
            "Live capture on {iface} needs read and write access to /dev/bpf*: install "
            "Wireshark's ChmodBPF, which grants it to the access_bpf group, add this user to that "
            "group, quit and reopen Zelos, then start the extension again",
        ),
        (NoBpfDevice, None),
    ],
    ids=["linux", "macos", "other error"],
)
def test_live_capture_without_capture_rights(
    agent_mode,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    socket: type,
    error: str | None,
) -> None:
    """The OS refuses the capture socket: one ERROR line says what is missing and how to grant
    it, Get Status reports not running, and Convert Pcap still converts. Any other capture
    error keeps its traceback."""
    from scapy.config import conf

    monkeypatch.setattr(conf, "L2listen", socket)
    converter = _converter(agent_mode, monkeypatch, {"interface": conf.loopback_name})
    errors = [(r.getMessage(), r.exc_info) for r in caplog.records if r.levelno >= logging.ERROR]
    if error is None:
        assert [(message, info[0]) for message, info in errors] == [
            ("V2G live capture stopped on error", Scapy_Exception)
        ]
    else:
        assert errors == [(error.format(iface=conf.loopback_name), None)]
    assert converter.get_status() == {"running": False}
    trz = tmp_path / "session.trz"
    assert converter.convert_pcap(str(FIXTURE), str(trz))["status"] == "success"
    assert trz.exists()
