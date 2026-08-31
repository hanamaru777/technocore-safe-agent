#!/usr/bin/env python3
"""Launch the approved Contribution #2 publisher without touching legacy observer state.

The isolated signer account deliberately cannot traverse the observer directory. Production
Autopilot state already lives in the dedicated shared state directory, so this launcher makes
`autopilot.status()` read that state with `allow_legacy=False` and then runs the fixed-function
publisher unchanged.
"""
from __future__ import annotations

import runpy

from flop_agent import autopilot, core

_original_status = autopilot.status


def dedicated_status(state: dict | None = None) -> dict:
    if state is None:
        state = autopilot.load(allow_legacy=False)
    return _original_status(state)


autopilot.status = dedicated_status
runpy.run_path(str(core.ROOT / "scripts" / "publish_field_report_v1.py"), run_name="__main__")
