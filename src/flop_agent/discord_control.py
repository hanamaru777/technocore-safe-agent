"""Optional, outbound-only Discord control plane for local Resident state."""
from __future__ import annotations

import asyncio
import logging
import os
import re
from datetime import UTC, datetime, timedelta

from . import autopilot, observer, resident

LOG = logging.getLogger(__name__)
URL_RE = re.compile(r"https?://\S+", re.I)
CATEGORY_LABELS = {
    "direct_inbound": "直接受信",
    "help_request": "具体的な支援依頼",
    "specific_question": "具体的な質問",
    "technical_collaboration": "技術コラボ候補",
    "artifact_contribution": "Contribution候補",
    "interesting_returning_agent": "再会した有用Agent",
    "new_high_quality_agent": "新しい有用Agent",
}
PRIORITY_LABELS = {"critical": "緊急", "high": "高", "medium": "中", "low": "低"}


def short(value: object, limit: int = 500) -> str:
    """Render local facts and untrusted excerpts without interpreting their contents."""
    return str(value).replace("\n", " ")[:limit]


def safe_excerpt(value: object, limit: int = 180) -> str:
    """Make an untrusted excerpt readable without creating clickable URL previews."""
    text = URL_RE.sub("[URL省略]", str(value)).replace("\n", " ")
    return re.sub(r"\s+", " ", text).strip()[:limit]


def percent(value: object) -> str | None:
    if not isinstance(value, (int, float)):
        return None
    return f"{max(0, min(100, round(float(value) * 100)))}%"


def candidate_message(item: dict) -> str:
    context = item.get("context", {})
    signals = item.get("signals", {})
    category = CATEGORY_LABELS.get(item.get("category"), item.get("category", "不明"))
    priority = PRIORITY_LABELS.get(item.get("priority"), item.get("priority", "不明"))
    excerpt = safe_excerpt(context.get("excerpt", ""), 180)
    useful = percent(signals.get("useful_agent_probability"))
    noise = percent(signals.get("spam_noise_probability"))
    lines = [
        "🚨 Technocore 対応候補",
        f"種類: {category} / 優先度: {priority}",
        f"相手: {item.get('fingerprint', 'unknown')} | {item.get('room', '?')} #{item.get('seq', '?')}",
    ]
    if excerpt:
        lines.append(f"抜粋: {excerpt}")
    if useful is not None or noise is not None:
        parts = []
        if useful is not None:
            parts.append(f"有用度 {useful}")
        if noise is not None:
            parts.append(f"ノイズ {noise}")
        lines.append("判定: " + " / ".join(parts))
    lines.append(f"確認: /candidate {item.get('candidate_id', '')}")
    return "\n".join(lines)


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
            data = resident.resident_status(); return {"ok": True, "data": data, "message": f"状態: agents={data['agents_known']} pending={data['useful_candidates']} gaps={data['message_gaps']}"}
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
        if action == "/autopilot-status":
            data = autopilot.status(); return {"ok": True, "data": data, "message": f"Autopilot: enabled={data['enabled']} paused={data['paused']} queued={data['queued']}."}
        if action == "/autopilot-queue":
            data = autopilot.queue(); return {"ok": True, "data": data, "message": f"Autopilot queue: {len(data['outbox'])} structured public intents."}
        if action == "/autopilot-pause": return {"ok": True, "data": autopilot.pause(True), "message": "Autopilot outbox generation paused."}
        if action == "/autopilot-resume": return {"ok": True, "data": autopilot.pause(False), "message": "Autopilot outbox generation resumed locally; Discord cannot publish."}
        if action == "/help": return {"ok": True, "data": {}, "message": "Commands: /resident-status /intel /opportunities /agents /agent <id> /candidate <id> /approve <id> /reject <id> <reason> /pause /resume /learning /autopilot-status /autopilot-queue /autopilot-pause /autopilot-resume"}
        return {"ok": False, "error": "unsupported", "message": "Unsupported control command. Use /help."}

    def notifications(self) -> list[dict]:
        """Return only genuinely actionable notices, not every heuristic high candidate."""
        state = resident.load_state(); notices = []
        current = datetime.now(UTC)
        recent = [entry for entry in state.get("notification_times", []) if (observer.parse_time(entry.get("at")) or current) > current - timedelta(hours=1)]
        state["notification_times"] = recent
        capacity = max(0, 3 - len(recent))
        for item in state["candidates"].values():
            if capacity <= 0: break
            if item.get("status") != "pending" or item.get("candidate_id") in state["notifications"]: continue
            signals = item.get("signals", {})
            legacy_high = item.get("priority") == "high" and not signals
            actionable = item.get("priority") == "critical" or signals.get("direct_public_signed") is True or legacy_high
            if not actionable: continue
            state["notifications"].append(item["candidate_id"])
            state["notification_times"].append({"candidate_id": item["candidate_id"], "at": current.isoformat()})
            notices.append(item); capacity -= 1
        resident.save_state(state); return notices

    def digest(self) -> str:
        status = resident.resident_status()
        state = resident.load_state()
        auto = autopilot.status()
        critical_pending = sum(item.get("status") == "pending" and item.get("priority") == "critical" for item in state["candidates"].values())
        direct_pending = sum(item.get("status") == "pending" and item.get("signals", {}).get("direct_public_signed") is True for item in state["candidates"].values())
        health = status.get("health", {}).get("current", "unknown") if isinstance(status.get("health"), dict) else "unknown"
        healthy = health == "ok" and not status.get("paused") and auto.get("enabled") and not auto.get("paused")
        icon = "🟢" if healthy else "🟠"
        auto_label = "ON" if auto.get("enabled") and not auto.get("paused") else "停止/一時停止"
        conclusion = "今すぐ対応不要。24時間監視を継続中。" if healthy and not critical_pending and not direct_pending else "要確認項目あり。上の件数を確認してください。"
        return (
            f"{icon} FLOP Agent 1時間レポート\n"
            f"稼働: {health} / Autopilot {auto_label} / queue {auto.get('queued', 0)}\n"
            f"監視: Agent {status['agents_known']} / ノイズ除外 {status['noise_ignored']} / 再会 {status['returning_agents']}\n"
            f"要対応: 緊急 {critical_pending} / 直接リクエスト {direct_pending} / 投稿記録 {auto.get('receipts', 0)}\n"
            f"結論: {conclusion}"
        )


def validate_environment() -> tuple[str, str, set[str]]:
    token, channel = os.environ.get("DISCORD_BOT_TOKEN"), os.environ.get("DISCORD_CHANNEL_ID", "")
    allowed = {item.strip() for item in os.environ.get("DISCORD_ALLOWED_USER_IDS", "").split(",") if item.strip()}
    if not token: raise RuntimeError("Discord token is missing")
    if not channel.isdecimal(): raise RuntimeError("Discord channel ID must be numeric")
    if not allowed or not all(item.isdecimal() for item in allowed): raise RuntimeError("Discord allowed user IDs must be non-empty numeric IDs")
    return token, channel, allowed


async def notification_worker(channel, control: Control, stop: asyncio.Event) -> None:
    while not stop.is_set():
        for item in await asyncio.to_thread(control.notifications):
            await channel.send(candidate_message(item), suppress_embeds=True)
        try: await asyncio.wait_for(stop.wait(), timeout=15)
        except TimeoutError: pass


async def digest_worker(channel, control: Control, stop: asyncio.Event) -> None:
    while not stop.is_set():
        try: await asyncio.wait_for(stop.wait(), timeout=resident.load_config().get("discord_digest_interval_seconds", 3600))
        except TimeoutError: await channel.send(await asyncio.to_thread(control.digest), suppress_embeds=True)


def main() -> None:
    token, channel_id, allowed = validate_environment()
    try: import discord
    except ImportError as error: raise SystemExit("Install the optional discord dependency to run this gateway") from error
    intents = discord.Intents.default(); intents.message_content = True
    bot = discord.Client(intents=intents); control = Control(allowed, channel_id); stop = asyncio.Event()
    @bot.event
    async def on_ready():
        channel = bot.get_channel(int(channel_id))
        if channel is None: raise RuntimeError("configured Discord channel is unavailable")
        if getattr(bot, "resident_workers_started", False): return
        bot.resident_workers_started = True
        LOG.info("Discord control started; message-content intent must be enabled in the Discord developer portal")
        asyncio.create_task(notification_worker(channel, control, stop)); asyncio.create_task(digest_worker(channel, control, stop))
    @bot.event
    async def on_message(message):
        if message.author.bot or str(message.channel.id) != channel_id: return
        result = await asyncio.to_thread(control.command, str(message.author.id), message.content, str(message.channel.id))
        await message.channel.send(result["message"], suppress_embeds=True)
    bot.run(token)


if __name__ == "__main__": main()
