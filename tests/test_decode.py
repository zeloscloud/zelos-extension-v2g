"""The zelos-packet seam: how it refuses, and the installed wheel decoding the
bundled captures through the extension's own convert path."""

from __future__ import annotations

import inspect
import shutil
from pathlib import Path

import pytest

from zelos_extension_v2g import actions, decode, pkg
from zelos_extension_v2g.capture import CaptureSession, InterfaceConfig
from zelos_extension_v2g.demo import DEMO_PCAP

from .conftest import FILES, FakeCapture


class TestRequire:
    def test_a_package_without_the_decoder_is_refused_by_version(self, fake_packet, monkeypatch):
        monkeypatch.delattr(fake_packet.Metrics, "v2g_tls_decrypted")
        monkeypatch.setattr(decode, "installed_version", lambda: "0.0.6")
        with pytest.raises(RuntimeError, match=r"needs zelos-packet>=0\.0\.7; installed 0\.0\.6"):
            CaptureSession(InterfaceConfig("en0", "en0"), "V2G").start()
        assert FakeCapture.instances == []

    def test_a_missing_package_is_its_own_message(self, monkeypatch):
        monkeypatch.setattr(pkg, "available", lambda: False)
        monkeypatch.setattr(pkg, "skip_reason", lambda: "zelos-packet is not installed")
        with pytest.raises(RuntimeError, match="not installed"):
            decode.require()


class TestInstalledWheel:
    def test_every_counter_and_keyword_exists_in_the_installed_wheel(self):
        import zelos_packet

        assert decode.supported()
        assert [c for c in decode.COUNTERS if not hasattr(zelos_packet.Metrics, c)] == []
        session = CaptureSession(InterfaceConfig("lo", "lo"), "V2G")
        accepted = inspect.signature(zelos_packet.PacketCapture).parameters
        assert [k for k in session.capture_kwargs() if k not in accepted] == []

    def test_the_demo_converts_to_a_whole_session(self, tmp_path: Path):
        pcap = Path(shutil.copy(DEMO_PCAP, tmp_path / DEMO_PCAP.name))
        result = actions.convert(str(pcap))
        assert Path(result["output_file"]) == tmp_path / "v2g-demo.trz"
        assert (result["status"], result["packets"], result["v2g_sdp_frames"]) == (
            "success",
            155,
            2,
        )
        assert result["v2g_messages"] == result["v2g_decoded"] == 68
        assert (
            result["v2g_undecoded"] == result["v2g_framing_errors"] == result["v2g_tcp_gaps"] == 0
        )

    def test_a_tls_session_decodes_only_with_its_key_log(self, tmp_path: Path):
        pcap = FILES / "iso2-tls.pcap"
        opaque = actions.convert(str(pcap), str(tmp_path / "opaque.trz"))
        assert (opaque["v2g_tls_connections"], opaque["v2g_tls_no_secret"]) == (1, 1)
        assert (opaque["status"], opaque["v2g_messages"]) == ("warning", 0)
        clear = actions.convert(
            str(pcap), str(tmp_path / "clear.trz"), tls_keylog=str(FILES / "iso2-tls.keys")
        )
        assert (clear["v2g_tls_decrypted"], clear["v2g_tls_no_secret"]) == (1, 0)
        assert clear["v2g_messages"] == clear["v2g_decoded"] == 72
