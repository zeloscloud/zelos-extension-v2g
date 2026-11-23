"""CLI and app-mode wiring: replay, the start policy, and the entry module."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner
from zelos_sdk.extensions import load_config

from zelos_extension_v2g.cli import app
from zelos_extension_v2g.converter import resolve_output
from zelos_extension_v2g.demo import DEMO_PCAP

from .conftest import FILES, SCHEMA_PATH, FakeCapture, FakeDecoder


@pytest.fixture
def app_config(fake_packet, monkeypatch) -> dict:
    """`run_app_mode` reads this dict as its config; no agent, no signal handlers."""
    config: dict = {}
    monkeypatch.setattr(app, "load_config", lambda: config)
    monkeypatch.setattr(app, "init_sdk", lambda _prefix: None)
    monkeypatch.setattr(app, "_install_replay_shutdown", lambda: None)
    monkeypatch.setattr(app, "_install_shutdown", lambda stop: stop.set())
    return config


class TestAppMode:
    def test_demo_flag_replays_the_bundled_capture_once_and_exits(self, app_config):
        import main

        result = CliRunner().invoke(main.cli, ["--demo"])
        assert result.exit_code == 0, result.output
        [decoder] = FakeDecoder.instances
        assert decoder.path == str(DEMO_PCAP)
        assert decoder.realtime is True and decoder.flushed
        assert (decoder.kwargs["name"], decoder.kwargs["source"].name) == ("v2g-demo", "V2G")
        assert decoder.kwargs["v2g"] is True

    def test_replay_ignores_interfaces_and_takes_the_key_log(self, app_config):
        keys = FILES / "iso2-tls.keys"
        app_config.update(
            interfaces=[{"interface": "en0"}],
            tls_keylog=str(keys),
            advanced={"replay_pcap": str(FILES / "iso2-tls.pcap")},
        )
        app.run_app_mode(False, None)
        assert FakeCapture.instances == []
        [decoder] = FakeDecoder.instances
        assert decoder.kwargs["tls_keylog"] == str(keys.resolve())

    def test_live_settings_reach_every_capture(self, app_config, tmp_path: Path):
        keys = tmp_path / "not-written-yet.log"
        app_config.update(
            interfaces=[{"interface": "en0"}, {"interface": "en1", "name": "charger"}],
            tls_keylog=str(keys),
            advanced={"prefix": "Bench", "promiscuous": False},
        )
        app.run_app_mode(False, None)
        assert [(c.kwargs["source_name"], c.kwargs["name"]) for c in FakeCapture.instances] == [
            ("Bench", "en0"),
            ("Bench", "charger"),
        ]
        for capture in FakeCapture.instances:
            assert capture.kwargs["v2g"] is True
            assert capture.kwargs["tls_keylog"] == str(keys.resolve())
            assert capture.kwargs["promiscuous"] is False
            assert capture.kwargs["snaplen"] == 0
            # No filter, and the package's own agent exclusion.
            assert capture.kwargs["filter"] is None
            assert capture.kwargs["exclude_agent_addrs"] is None
            assert capture.started and capture.stopped

    def test_one_interface_failing_fails_the_whole_start(self, app_config, caplog):
        app_config["interfaces"] = [{"interface": "en0"}, {"interface": "nope0"}]
        with pytest.raises(SystemExit, match="1"):
            app.run_app_mode(False, None)
        assert "Interface 'nope0' was not found on this machine" in caplog.text
        good, bad = FakeCapture.instances
        assert good.stopped and not bad.started

    def test_nothing_configured_fails_with_one_line(self, app_config, caplog):
        with pytest.raises(SystemExit, match="1"):
            app.run_app_mode(False, None)
        assert "Nothing to do" in caplog.text
        assert FakeDecoder.instances == []

    def test_settings_that_fail_the_check_fail_with_one_line(
        self, app_config, monkeypatch, caplog, tmp_path: Path
    ):
        saved = tmp_path / "config.json"
        saved.write_text('{"advanced": {"log_level": "LOUD"}}')
        monkeypatch.setattr(
            app, "load_config", lambda: load_config(config_path=saved, schema_path=SCHEMA_PATH)
        )
        with pytest.raises(SystemExit, match="1"):
            app.run_app_mode(False, None)
        assert "Invalid configuration: advanced.log_level: 'LOUD'" in caplog.text


class TestEntry:
    def test_group_lists_every_subcommand(self):
        import main

        result = CliRunner().invoke(main.cli, ["--help"])
        assert result.exit_code == 0
        for cmd in ("interfaces", "check", "capture", "replay", "convert"):
            assert cmd in result.output

    def test_an_empty_prefix_is_refused_before_capture(self, fake_packet):
        import main

        result = CliRunner().invoke(main.cli, ["capture", "en0", "--prefix", ""])
        assert result.exit_code != 0
        assert "must not be empty" in result.output
        assert FakeCapture.instances == []

    def test_output_defaults_and_overwrite(self, tmp_path: Path):
        assert resolve_output(Path("/c/run1.pcapng.gz")) == Path("/c/run1.trz")
        existing = tmp_path / "run1.trz"
        existing.touch()
        with pytest.raises(FileExistsError):
            resolve_output(tmp_path / "run1.pcap")
        assert resolve_output(tmp_path / "run1.pcap", overwrite=True) == existing
