"""Agent mode applies its configuration. No running Zelos agent is needed."""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest
import zelos_sdk

from zelos_extension_v2g.cli import app
from zelos_extension_v2g.extension import V2gConverter


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
