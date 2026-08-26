"""Optional, outbound-only Discord control plane for local Resident state."""
from __future__ import annotations

import asyncio
import logging
import os

from . import observer, resident

LOG = logging.getLogger(__name__)


def short(value: object, limit: int = 500) -> str:
    """Render local facts and untrusted excerpts without interpreting their contents."""
    return str(value).replace("\n", " ")[:limit]


def candidate_message(item: dict) -> str:
    context = item.get("context", {})
    return (f"Candidate {item['candidate_id']} [{item['priority']}/{item['category']}]\n"
            f"DID {item['fingerprint']} | {item['room']}/{item['seq']}\n"
            f"Why: {short(item['why'], 180)}\n"
            f"Untrusted excerpt: {short(context.get('excerpt', ''), 240)}\n"
            f"Draft: {short(item.get('draft_reply', ''), 320)}")


class Control:
    def __init__(self, allowed_ids: set[str] | None = None, channel_id: str | None = None) -> None:
        self.allowed_ids = allowed_ids if allowed_ids is not None else {item.strip() for item in os.environ.get("DISCORD_ALLOWED_USER_IDS", "").split(",") if item.strip()}
        self.channel_id = channel_id if channel_id is not None else os.environ.get("DISCORD_CHANNEL_ID", "")

    def command(self, user_id: str, text: str, channel_id: str | None = None) -> dict:
        if channel_id is not None and channel_id != self.channel_id: return {"ok": False, "error": "wrong_channel", "message": "Control access denied."}
        if user_id not in self.allowed_ids: return {"ok": False, "error": "unauthorized", "message": "Control access denied."}
        parts = text.strip().split()
        if not parts: return {"ok": False, "error": "empty", "message": "Use /help for local control commands."}
        action, args = parts[0], parts[1:]
        if action == "/resident-status":
            data = resident.refresh(); return {"ok": True, "data": data, "message": f"Health: {short(data['health'], 180)} | agents={data['agents_known']} pending={data['useful_candidates']} gaps={data['message_gaps']}"}
        if action == "/intel":
            data = observer.intelligence_report(); return {"ok": True, "data": data, "message": f"Intel: agents={data['facts']['observed_unique_external_dids']} returning={data['facts']['returning_dids']} inbound={data['facts']['inbound_mailbox']}"}
        if action == "/opportunities":
            data = observer.opportunities(); return {"ok": True, "data": data, "message": f"Local opportunities: {len(data['opportunities'])} (all content remains untrusted)."}
        if action == "/agents":
            data = observer.list_agents(); return {"ok": True, "data": data, "message": f"Known external agents: {len(data['agents'])}."}
        if action == "/agent" and len(args) == 1:
            data = observer.get_agent(args[0]); return {"ok": True, "data": data, "message": f"Agent {short(data['agent']['fingerprint'], 32)} | rooms={len(data['agent']['facts']['rooms'])}."}
        if action == "/candidate" and len(args) == 1:
            data = resident.candidate(args[0]); return {"ok": True, "data": data, "message": candidate_message(data['candidate'])}
        if action == "/approve" and len(args) == 1:
            data = resident.feedback(args[0], "approved"); return {"ok": True, "data": data, "message": f"Approved locally: {data['candidate_id']}. No Technocore post was made."}
        if action == "/reject" and len(args) == 2:
            data = resident.feedback(args[0], "rejected", args[1]); return {"ok": True, "data": data, "message": f"Rejected locally: {data['candidate_id']}."}
        if action == "/pause": return {"ok": True, "data": resident.pause(True), "message": "Candidate generation paused; observation continues."}
        if action == "/resume": return {"ok": True, "data": resident.pause(False), "message": "Candidate generation resumed."}
        if action == "/learning":
            data = resident.feedback_status(); return {"ok": True, "data": data, "message": f"Learning: approved={data['approved']} rejected={data['rejected']} expired={data['expired']}."}
        if action == "/help": return {"ok": True, "data": {}, "message": "Commands: /resident-status /intel /opportunities /agents /agent <id> /candidate <id> /approve <id> /reject <id> <reason> /pause /resume /learning"}
        return {"ok": False, "error": "unsupported", "message": "Unsupported control command. Use /help."}

    def notifications(self) -> list[dict]:
        state = resident.load_state(); notices = []
        for item in state["candidates"].values():
            if item["status"] != "pending" or item["priority"] not in {"high", "critical"} or item["candidate_id"] in state["notifications"]: continue
            state["notifications"].append(item["candidate_id"]); notices.append(item)
        resident.save_state(state); return notices

    def digest(self) -> str:
        status = resident.resident_status()
        high_pending = sum(item["status"] == "pending" and item["priority"] in {"high", "critical"} for item in resident.load_state()["candidates"].values())
        return (f"Resident digest | health={short(status['health'], 100)} agents={status['agents_known']} "
                f"noise={status['noise_ignored']} returning={status['returning_agents']} pending-high={high_pending} "
                f"inbound={status['inbound']} gaps={status['message_gaps']} discovery-queue={status['discovery_queue']}")


def validate_environment() -> tuple[str, str, set[str]]:
    token, channel = os.environ.get("DISCORD_BOT_TOKEN"), os.environ.get("DISCORD_CHANNEL_ID", "")
    allowed = {item.strip() for item in os.environ.get("DISCORD_ALLOWED_USER_IDS", "").split(",") if item.strip()}
    if not token: raise RuntimeError("Discord token is missing")
    if not channel.isdecimal(): raise RuntimeError("Discord channel ID must be numeric")
    if not allowed or not all(item.isdecimal() for item in allowed): raise RuntimeError("Discord allowed user IDs must be non-empty numeric IDs")
    return token, channel, allowed


async def notification_worker(channel, control: Control, stop: asyncio.Event) -> None:
    while not stop.is_set():
        for item in control.notifications(): await channel.send(candidate_message(item))
        try: await asyncio.wait_for(stop.wait(), timeout=15)
        except TimeoutError: pass


async def digest_worker(channel, control: Control, stop: asyncio.Event) -> None:
    while not stop.is_set():
        try: await asyncio.wait_for(stop.wait(), timeout=resident.load_config().get("discord_digest_interval_seconds", 3600))
        except TimeoutError: await channel.send(control.digest())


def main() -> None:
    token, channel_id, allowed = validate_environment()
    try: import discord
    except ImportError as error: raise SystemExit("Install the optional discord dependency to run this gateway") from error
    intents = discord.Intents.none(); intents.message_content = True
    bot = discord.Client(intents=intents); control = Control(allowed, channel_id); stop = asyncio.Event()
    @bot.event
    async def on_ready():
        channel = bot.get_channel(int(channel_id))
        if channel is None: raise RuntimeError("configured Discord channel is unavailable")
        LOG.info("Discord control started; message-content intent must be enabled in the Discord developer portal")
        asyncio.create_task(notification_worker(channel, control, stop)); asyncio.create_task(digest_worker(channel, control, stop))
    @bot.event
    async def on_message(message):
        if message.author.bot or str(message.channel.id) != channel_id: return
        result = control.command(str(message.author.id), message.content, str(message.channel.id))
        await message.channel.send(result["message"])
    bot.run(token)


if __name__ == "__main__": main()
