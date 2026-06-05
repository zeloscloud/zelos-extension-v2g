"""`decode` subcommand: decode a pcap byte stream from stdin -> live Zelos trace."""

from __future__ import annotations

import sys

import rich_click as click


@click.command()
@click.option("--source-name", default="v2g", help="Trace source name")
def decode(source_name: str) -> None:
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

    run_decode(source_name=source_name)
