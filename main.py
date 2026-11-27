#!/usr/bin/env python3
"""Zelos V2G extension - ISO 15118 / DIN 70121 charging links, live or from a capture."""

import logging
import time
from pathlib import Path

import rich_click as click

from zelos_extension_v2g import ACTION_PREFIX as _ACTION_PREFIX
from zelos_extension_v2g import cli as cli_commands

#: Re-exported so the at-rest inventory dump - which reads this entry module -
#: addresses the actions the same way the live registration does. Without it the
#: dump falls back to the module name and ships them under `main/`.
ACTION_PREFIX = _ACTION_PREFIX

click.rich_click.TEXT_MARKUP = "markdown"
click.rich_click.SHOW_ARGUMENTS = True
click.rich_click.GROUP_ARGUMENTS_OPTIONS = True
click.rich_click.STYLE_ERRORS_SUGGESTION = "yellow italic"

# UTC ISO 8601 with ms, matching the SDK's Rust tracing lines in the same log stream.
logging.Formatter.converter = time.gmtime
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03dZ %(levelname)5s %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)


@click.group(invoke_without_command=True)
@click.option(
    "--demo", is_flag=True, help="Replay the bundled demo capture until stopped, as Demo does"
)
@click.option(
    "--file",
    type=click.Path(path_type=Path),
    default=None,
    is_flag=False,
    flag_value=".",
    help="Record trace to .trz file (defaults to UTC.trz if no filename specified)",
)
@click.pass_context
def cli(ctx: click.Context, demo: bool, file: Path | None) -> None:
    """ISO 15118 / DIN 70121 EV charging (V2G) decode.

    With no subcommand this runs in app-config mode - the way the Zelos
    supervisor launches it - reading `config.json` against `config.schema.json`.
    """
    if ctx.invoked_subcommand is not None:
        return
    cli_commands.run_app_mode(demo, file)


cli.add_command(cli_commands.interfaces_cmd)
cli.add_command(cli_commands.check_cmd)
cli.add_command(cli_commands.capture_cmd)
cli.add_command(cli_commands.replay_cmd)
cli.add_command(cli_commands.convert_cmd)


if __name__ == "__main__":
    cli()
