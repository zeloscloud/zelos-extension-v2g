"""`decode` subcommand: decode a pcap byte stream from stdin -> live Zelos trace."""

from __future__ import annotations

import sys
from pathlib import Path

import rich_click as click

from ..config import DEFAULT_PREFIX


@click.command()
@click.option(
    "--prefix",
    default=DEFAULT_PREFIX,
    show_default=True,
    help="Leading trace-source name; pass '' to name the source after --name",
)
@click.option("--name", default="stdin", show_default=True, help="Branch name for the stream")
@click.option(
    "-d",
    "--dbc",
    type=click.Path(exists=True, path_type=Path),
    help="CAN database (.dbc) — decode CAN frames into named signals (raw frames are always kept)",
)
def decode(prefix: str, name: str, dbc: Path | None) -> None:
    """Decode a pcap stream piped on **stdin** into the live Zelos app.

    The network analog of `candump | cantools decode`: pipe a capture tool's pcap
    output straight in — e.g. live off a remote bench over SSH:

      ssh root@bench "tcpdump -i eth0 -U -s0 -w - 'ip6 or ether proto 0x88e1'" \\
        | zelos-extension-v2g decode

    Use `-i eth0` (Ethernet) or `-i any` (Linux cooked / SLL) — both decode. The
    `'ip6 or ether proto 0x88e1'` filter keeps SLAC + SDP + V2GTP; do **not** filter
    on `tcp` alone (you would drop SLAC and SDP).
    """
    if sys.stdin.isatty():
        raise click.UsageError(
            "no pcap on stdin — pipe one in, e.g.:\n"
            "  tcpdump -i eth0 -U -s0 -w - 'ip6 or ether proto 0x88e1' | zelos-extension-v2g decode"
        )
    from ..live import run_decode

    run_decode(prefix=prefix, name=name, dbc=str(dbc) if dbc else None)
