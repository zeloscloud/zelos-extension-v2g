"""Pins each action's flags, so a new action or a changed flag is a deliberate choice."""

from __future__ import annotations

import inspect

from zelos_extension_v2g.extension import V2gConverter


def test_every_action_has_its_flags():
    actual = {
        name: (obj._action.read_only, obj._action.hidden)
        for name, obj in inspect.getmembers(V2gConverter, inspect.isfunction)
        if not name.startswith("_") and hasattr(obj, "_action")
    }
    assert actual == {
        "convert_pcap": (False, False),
        "get_status": (True, True),
    }
