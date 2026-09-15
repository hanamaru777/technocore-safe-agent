"""Final Discord entrypoint with durable Agent activity cockpit notices."""
from __future__ import annotations

from . import discord_agent_activity
from . import discord_tclk_approval as app

_ORIGINAL_COMBINED = app._combined_notices


def _combined_with_agent_activity() -> list[str]:
    return [*_ORIGINAL_COMBINED(), *discord_agent_activity.poll_notices()]


def main() -> None:
    app._combined_notices = _combined_with_agent_activity
    app.main()


if __name__ == "__main__":
    main()
