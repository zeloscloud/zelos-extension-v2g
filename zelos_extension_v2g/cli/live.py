"""`live` subcommand: live V2G capture or pcap replay -> live Zelos trace."""

from __future__ import annotations

from pathlib import Path

import rich_click as click


@click.command()
@click.option(
    "--iface",
    default=None,
    help="Interface to sniff for live capture (needs root + a bridged PLC/green-PHY link)",
)
@click.option(
    "--replay",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Replay a pcap/pcapng as a live stream (same code path; for testing/demo)",
)
@click.option("--source-name", default="v2g", help="Trace source name")
def live(iface: str | None, replay: Path | None, source_name: str) -> None:
    """Stream live V2G telemetry into the Zelos app.

    Examples:

      zelos-extension-v2g live --iface eth0

      zelos-extension-v2g live --replay session.pcapng
    """
    if not iface and not replay:
        raise click.UsageError("provide --iface (live capture) or --replay <pcap> (testing)")
    from ..live import run_live

    run_live(iface=iface, replay=str(replay) if replay else None, source_name=source_name)
