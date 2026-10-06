#!/usr/bin/env python3
"""Zelos V2G extension — ISO 15118 / DIN 70121 pcap decode and trace conversion."""

import logging
import time

import rich_click as click

from zelos_extension_v2g import ACTION_PREFIX as _ACTION_PREFIX
from zelos_extension_v2g import cli as cli_commands

#: Re-exported so the at-rest inventory dump, which reads this entry module,
#: addresses the actions the same way the live registration does.
ACTION_PREFIX = _ACTION_PREFIX

click.rich_click.USE_RICH_MARKUP = True
click.rich_click.USE_MARKDOWN = True
click.rich_click.SHOW_ARGUMENTS = True

# UTC ISO 8601 with ms, matching the SDK's Rust tracing lines in the same log stream
logging.Formatter.converter = time.gmtime
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03dZ %(levelname)5s %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """ISO 15118 / DIN 70121 V2G decode and pcap→trace conversion.

    With no subcommand, runs in agent mode: captures the configured interfaces and
    hosts the `V2G/` actions. Use `convert` to convert a capture from the command line.
    """
    if ctx.invoked_subcommand is not None:
        return
    cli_commands.run_app_mode()


cli.add_command(cli_commands.convert)
cli.add_command(cli_commands.live)
cli.add_command(cli_commands.decode)


if __name__ == "__main__":
    cli()
