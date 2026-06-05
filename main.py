#!/usr/bin/env python3
"""Zelos V2G extension — ISO 15118 / DIN 70121 pcap decode and trace conversion."""

import logging

import rich_click as click

from zelos_extension_v2g import cli as cli_commands

click.rich_click.USE_RICH_MARKUP = True
click.rich_click.USE_MARKDOWN = True
click.rich_click.SHOW_ARGUMENTS = True

logging.basicConfig(level=logging.INFO)


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """ISO 15118 / DIN 70121 V2G decode and pcap→trace conversion.

    With no subcommand, runs in agent mode and exposes the **Convert Pcap** action.
    Use the `convert` subcommand to convert a capture from the command line.
    """
    if ctx.invoked_subcommand is not None:
        return
    cli_commands.run_app_mode()


cli.add_command(cli_commands.convert)
cli.add_command(cli_commands.live)
cli.add_command(cli_commands.decode)


if __name__ == "__main__":
    cli()
