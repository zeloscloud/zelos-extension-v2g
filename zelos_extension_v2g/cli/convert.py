"""`convert` subcommand: V2G pcap -> Zelos trace."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import rich_click as click

logger = logging.getLogger(__name__)


@click.command()
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-o", "--output", type=click.Path(path_type=Path), help="Output .trz file (default: input.trz)"
)
@click.option("-f", "--force", is_flag=True, help="Overwrite the output file if it exists")
@click.option("-v", "--verbose", is_flag=True, help="Verbose debug logging")
def convert(input_file: Path, output: Path | None, force: bool, verbose: bool) -> None:
    """Convert an ISO 15118 / DIN 70121 V2G capture (.pcap) to Zelos trace format.

    Examples:

      zelos-extension-v2g convert session.pcap

      zelos-extension-v2g convert session.pcap -o out.trz -f
    """
    from ..converter import convert_v2g_pcap, resolve_trz_output

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO, format="%(levelname)s: %(message)s"
    )

    try:
        output_file = resolve_trz_output(input_file, output, force)
        stats = convert_v2g_pcap(input_file, output_file)
    except FileExistsError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        logger.error("Conversion failed: %s", e)
        if verbose:
            raise
        sys.exit(1)

    d = stats.to_dict()
    click.echo("\n✓ Conversion complete!")
    click.echo(f"  Input:    {input_file}")
    click.echo(f"  Output:   {output_file}")
    click.echo(f"  Protocol: {d['protocol'] or 'unknown'}")
    click.echo(f"  SLAC:     {d['slac_frames']} frames")
    click.echo(f"  SDP:      {d['sdp_frames']} frames")
    click.echo(f"  Messages: {d['messages']} ({d['decoded_messages']} decoded)")
    click.echo(f"  Duration: {d['duration_seconds']}s")
