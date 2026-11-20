"""The action surface: names, flags, and the read-only actions over a fake capture."""

from __future__ import annotations

from zelos_sdk.actions import ActionsRegistry

from zelos_extension_v2g import actions, decode
from zelos_extension_v2g import capture as capture_mod
from zelos_extension_v2g.capture import CaptureSession, InterfaceConfig, replay_pcap
from zelos_extension_v2g.demo import DEMO_PCAP

from .conftest import FakeDecoder


def test_actions_register_under_their_bare_names_and_flags_are_pinned():
    registered = actions.register_actions(ActionsRegistry())
    flags = {
        name: (getattr(actions, name)._action.read_only, getattr(actions, name)._action.hidden)
        for name in registered
    }
    # Every action is read-only: nothing is ever sent on the link.
    assert flags == {
        "auto_config": (True, True),
        "list_interfaces": (True, True),
        "check_permissions": (True, False),
        "get_status": (True, False),
        "convert_pcap": (True, False),
        "demo_capture_path": (True, False),
    }
    assert actions.demo_capture_path()["path"] == str(DEMO_PCAP)
    assert DEMO_PCAP.is_file()


def test_get_status_reports_nothing_running():
    actions.CAPTURES.clear()
    assert actions.get_status()["status"] == "warning"


def test_status_over_a_running_capture_carries_every_v2g_counter(fake_packet):
    session = CaptureSession(InterfaceConfig("en0", "en0"), "V2G")
    session.start()
    actions.CAPTURES.clear()
    actions.CAPTURES["en0"] = session
    try:
        [status] = actions.get_status()["interfaces"]
        assert status["running"] and status["packets_read"] == 12
        assert (status["v2g_decoded"], status["v2g_tls_connections"]) == (8, 1)
        assert set(decode.COUNTERS) <= set(status)
    finally:
        actions.CAPTURES.clear()
        session.stop()


def test_a_running_replay_answers_like_a_capture(fake_packet, monkeypatch):
    seen = {}

    def convert_file(self, path, *, realtime=False):
        seen.update(status=actions.get_status())
        return 0

    monkeypatch.setattr(FakeDecoder, "convert_file", convert_file)
    actions.CAPTURES.clear()
    replay_pcap(DEMO_PCAP, name="demo", prefix="V2G")
    assert seen["status"]["interfaces"][0]["v2g_decoded"] == 8
    assert capture_mod.REPLAYS == {}


def test_list_interfaces_and_auto_config_follow_the_form_contracts(fake_packet):
    assert actions.list_interfaces()["choices"] == [
        {"value": "en0", "detail": "up · 10.0.0.5"},
        {"value": "lo0", "detail": "up · loopback · 127.0.0.1"},
    ]
    assert actions.auto_config()["config"] == {"interfaces": [{"interface": "en0"}]}


def test_check_permissions_without_the_package_still_carries_remediation(monkeypatch):
    from zelos_extension_v2g import pkg

    monkeypatch.setattr(pkg, "available", lambda: False)
    result = actions.check_permissions()
    assert result["status"] == "error"
    assert "Replay PCAP File" in result["remediation"]
