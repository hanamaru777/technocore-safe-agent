"""One-shot unprivileged stage producer for tclk first-pilot candidates."""
from __future__ import annotations

import json
import sys

from . import tclk_pilot


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("tclk pilot stager accepts no arguments")
    try:
        result = tclk_pilot.stage_pending()
    except tclk_pilot.PilotError as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        raise SystemExit(1)
    print(json.dumps({"ok": True, **result}, sort_keys=True))


if __name__ == "__main__":
    main()
