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
