"""`convert` subcommand: a CAN/V2G capture -> Zelos trace."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import rich_click as click

from ..config import DEFAULT_PREFIX

logger = logging.getLogger(__name__)


@click.command()
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-o", "--output", type=click.Path(path_type=Path), help="Output .trz file (default: input.trz)"
)
@click.option(
    "-d",
    "--dbc",
    "dbcs",
    multiple=True,
    type=click.Path(exists=True, path_type=Path),
    help="CAN database (.dbc), repeatable in precedence order (a later file wins). "
    "Decodes CAN frames into named signals; raw frames are always kept",
)
@click.option(
    "--prefix",
    default=DEFAULT_PREFIX,
    show_default=True,
    help="Leading trace-source name; pass '' to name the source after the input file",
)
@click.option("--no-packets", is_flag=True, help="Skip the per-frame '<stem>/packets' rows")
@click.option("-f", "--force", is_flag=True, help="Overwrite the output file if it exists")
@click.option("-v", "--verbose", is_flag=True, help="Verbose debug logging")
def convert(
    input_file: Path,
    output: Path | None,
    dbcs: tuple[Path, ...],
    prefix: str,
    no_packets: bool,
    force: bool,
    verbose: bool,
) -> None:
    """Convert a capture (.pcap/.pcapng) to Zelos trace format.

    Decodes both V2G (ISO 15118 / DIN 70121) and CAN in a single pass, so a
    capture with both — e.g. a bench recording of a charging session alongside
    the vehicle bus — becomes one time-aligned trace under
    ``<prefix>/<file stem>/``, with CAN at ``<file stem>/CAN/*``.

    Examples:

      zelos-extension-v2g convert session.pcapng

      zelos-extension-v2g convert combined.pcapng -d base.dbc -d overlay.dbc -o out.trz
    """
    from ..converter import convert_capture, resolve_trz_output

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO, format="%(levelname)s: %(message)s"
    )

    try:
        output_file = resolve_trz_output(input_file, output, force)
        stats = convert_capture(
            input_file, output_file, dbcs, prefix=prefix, log_packets=not no_packets
        )
    except (FileExistsError, ValueError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        logger.error("Conversion failed: %s", e)
        if verbose:
            raise
        sys.exit(1)

    d = stats.to_dict()
    v = d["v2g"]
    click.echo("\n✓ Conversion complete!")
    click.echo(f"  Input:    {input_file}")
    click.echo(f"  Output:   {output_file}")
    click.echo(f"  Duration: {d['duration_seconds']}s")
    if d["packets"]:
        click.echo(f"  Packets:  {d['packets']}")
    if d["can_frames"]:
        decoded = (
            f"{d['can_decoded_frames']} decoded" if d["database_files"] else "raw only (no --dbc)"
        )
        click.echo(f"  CAN:      {d['can_frames']} frames ({decoded})")
    if d["can_error_frames"] or d["can_bad_records"]:
        click.echo(
            f"  CAN skipped: {d['can_error_frames']} error frames, "
            f"{d['can_bad_records']} malformed records"
        )
    if d["frame_errors"]:
        click.echo(f"  Skipped:  {d['frame_errors']} (frames that failed to decode)")
    if v["messages"] or v["slac_frames"]:
        click.echo(f"  V2G:      {v['protocol'] or 'unknown'}")
        click.echo(f"            SLAC {v['slac_frames']} / SDP {v['sdp_frames']} frames")
        click.echo(f"            {v['messages']} messages ({v['decoded_messages']} decoded)")
        if v["tcp_retransmissions"]:
            click.echo(f"            {v['tcp_retransmissions']} retransmitted TCP segments dropped")
