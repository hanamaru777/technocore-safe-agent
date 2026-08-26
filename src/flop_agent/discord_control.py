"""Optional Discord control plane; no connection is made unless run as a module."""
from __future__ import annotations

import os

from . import observer, resident


class Control:
    def __init__(self, allowed_ids: set[str] | None = None) -> None:
        self.allowed_ids = allowed_ids if allowed_ids is not None else {item.strip() for item in os.environ.get("DISCORD_ALLOWED_USER_IDS", "").split(",") if item.strip()}
    def command(self, user_id: str, text: str) -> dict:
        if user_id not in self.allowed_ids: return {"ok": False, "error": "unauthorized"}
        parts = text.strip().split()
        if not parts: return {"ok": False, "error": "empty"}
        action, args = parts[0], parts[1:]
        if action == "/resident-status": return {"ok": True, "data": resident.refresh()}
        if action == "/intel": return {"ok": True, "data": observer.intelligence_report()}
        if action == "/opportunities": return {"ok": True, "data": observer.opportunities()}
        if action == "/agents": return {"ok": True, "data": observer.list_agents()}
        if action == "/agent" and len(args) == 1: return {"ok": True, "data": observer.get_agent(args[0])}
        if action == "/candidate" and len(args) == 1: return {"ok": True, "data": resident.candidate(args[0])}
        if action == "/approve" and len(args) == 1: return {"ok": True, "data": resident.feedback(args[0], "approved")}
        if action == "/reject" and len(args) == 2: return {"ok": True, "data": resident.feedback(args[0], "rejected", args[1])}
        if action == "/pause": return {"ok": True, "data": resident.pause(True)}
        if action == "/resume": return {"ok": True, "data": resident.pause(False)}
        if action == "/learning": return {"ok": True, "data": resident.feedback_status()}
        if action == "/help": return {"ok": True, "data": {"commands": ["/resident-status", "/intel", "/opportunities", "/candidate <id>", "/approve <id>", "/reject <id> <reason>", "/pause", "/resume"]}}
        return {"ok": False, "error": "unsupported"}
    def notifications(self) -> list[dict]:
        state = resident.load_state(); notices = []
        for item in state["candidates"].values():
            if item["priority"] not in {"high", "critical"} or item["candidate_id"] in state["notifications"]: continue
            state["notifications"].append(item["candidate_id"]); notices.append(item)
        resident.save_state(state); return notices


def main() -> None:
    token, channel = os.environ.get("DISCORD_BOT_TOKEN"), os.environ.get("DISCORD_CHANNEL_ID")
    if not token or not channel: raise SystemExit("Discord environment is incomplete")
    try: import discord
    except ImportError as error: raise SystemExit("Install discord.py to run the optional Discord gateway") from error
    intents = discord.Intents.none(); intents.message_content = True
    bot = discord.Client(intents=intents); control = Control()
    @bot.event
    async def on_message(message):
        if message.author.bot or str(message.channel.id) != channel: return
        result = control.command(str(message.author.id), message.content)
        await message.channel.send("accepted" if result["ok"] else "rejected")
    bot.run(token)


if __name__ == "__main__": main()
