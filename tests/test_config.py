"""Config: schema defaults, `parse_interfaces`, and the two agreeing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from zelos_sdk.extensions import load_config

from zelos_extension_v2g.capture import InterfaceConfig, parse_interfaces
from zelos_extension_v2g.cli.app import ADVANCED_DEFAULTS
from zelos_extension_v2g.decode import ConfigError, V2gConfig, parse_v2g

from .conftest import REPO_ROOT, SCHEMA_PATH


def load(tmp_path: Path, raw: dict) -> dict:
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(raw))
    return load_config(config_path=config_file, schema_path=SCHEMA_PATH)


class TestSchema:
    def test_empty_config_gets_the_defaults_app_mode_assumes(self, tmp_path: Path):
        config = load(tmp_path, {})
        assert config["interfaces"] == []
        assert config["advanced"] == ADVANCED_DEFAULTS
        assert ADVANCED_DEFAULTS == {"prefix": "V2G", "promiscuous": True, "log_level": "INFO"}

    def test_shipped_config_json_validates(self, tmp_path: Path):
        shipped = json.loads((REPO_ROOT / "config.json").read_text())
        assert load(tmp_path, shipped)["advanced"] == ADVANCED_DEFAULTS

    def test_an_empty_prefix_is_refused(self, tmp_path: Path):
        with pytest.raises(Exception, match="prefix: '' should be non-empty"):
            load(tmp_path, {"advanced": {"prefix": ""}})

    def test_a_removed_setting_is_refused(self, tmp_path: Path):
        with pytest.raises(Exception, match="database_files"):
            load(tmp_path, {"database_files": ["x.dbc"]})


class TestParse:
    def test_names_default_to_the_interface_sanitized(self):
        configs = parse_interfaces(
            {"interfaces": [{"interface": "eth0"}, {"interface": "eth0.100"}]}
        )
        assert configs == [InterfaceConfig("eth0", "eth0"), InterfaceConfig("eth0.100", "eth0_100")]

    @pytest.mark.parametrize(
        ("entry", "match"),
        [
            ({}, "missing 'interface'"),
            ({"interface": "eth0", "name": "a/b"}, "not allowed"),
            ({"interface": "eth0", "name": "log"}, "reserved"),
        ],
    )
    def test_bad_entries_name_the_field(self, entry: dict, match: str):
        with pytest.raises(ConfigError, match=match):
            parse_interfaces({"interfaces": [entry]})

    def test_duplicate_names_are_a_hard_error(self):
        with pytest.raises(ConfigError, match="Duplicate interface name"):
            parse_interfaces({"interfaces": [{"interface": "eth0.1"}, {"interface": "eth0:1"}]})

    def test_a_key_log_may_be_missing_only_for_live_capture(self, tmp_path: Path):
        missing = tmp_path / "keys.log"
        assert parse_v2g("", must_exist=True) == V2gConfig()
        assert parse_v2g(str(missing), must_exist=False) == V2gConfig(str(missing.resolve()))
        with pytest.raises(ConfigError, match="TLS key log file not found"):
            parse_v2g(str(missing), must_exist=True)
