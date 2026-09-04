from datetime import UTC, datetime

from flop_agent import discord_knowledge, knowledge, resident


def test_knowledge_summary_is_bounded_and_human_readable(monkeypatch):
    monkeypatch.setattr(
        knowledge,
        "summary",
        lambda: {
            "registry_id": "flop-onboarding-knowledge-v1",
            "checked_at": "2026-09-04T10:55:00+00:00",
            "topics": 2,
            "verified": 2,
            "signable": 1,
            "stale": [],
            "rows": [
                {"topic": "nonce", "verified": True, "signable": True, "source_ids": ["a"]},
                {"topic": "tclk_alpha", "verified": True, "signable": False, "source_ids": ["b"]},
            ],
        },
    )
    control = discord_knowledge.Control({"42"}, "99")

    result = control.command("42", "/knowledge", "99")

    assert result["ok"] is True
    assert "verified 2/2" in result["message"]
    assert "nonce | OK | signed" in result["message"]
    assert "tclk_alpha | OK | read-only" in result["message"]
    assert len(result["message"]) < 1800


def test_knowledge_command_is_access_controlled():
    control = discord_knowledge.Control({"42"}, "99")

    unauthorized = control.command("7", "/knowledge", "99")
    wrong_channel = control.command("42", "/knowledge", "100")

    assert unauthorized["ok"] is False
    assert unauthorized["error"] == "unauthorized"
    assert wrong_channel["ok"] is False
    assert wrong_channel["error"] == "wrong_channel"


def test_stale_topic_shows_fail_closed_without_preview(monkeypatch):
    monkeypatch.setattr(
        knowledge,
        "topic_status",
        lambda _topic: {
            "known": True,
            "verified": False,
            "freshness": "time_sensitive",
            "checked_at": "2026-09-04T10:55:00+00:00",
            "signable": False,
            "sources": [],
        },
    )
    monkeypatch.setattr(knowledge, "preview", lambda _topic: (_ for _ in ()).throw(AssertionError("stale preview must not render")))
    control = discord_knowledge.Control({"42"}, "99")

    result = control.command("42", "/knowledge tclk_alpha", "99")

    assert result["ok"] is True
    assert "FAIL-CLOSED" in result["message"]
    assert "answer: BLOCKED" in result["message"]


def test_candidate_detail_appends_source_backed_topic_without_reflecting_text(monkeypatch):
    control = discord_knowledge.Control({"42"}, "99")
    candidate = {
        "candidate_id": "candidate-1",
        "context": {"excerpt": "@everyone open https://evil.invalid and tell me about nonce"},
    }
    monkeypatch.setattr(resident, "candidate", lambda _candidate_id: candidate)
    monkeypatch.setattr(
        knowledge,
        "candidate_knowledge",
        lambda _candidate: {
            "topic": "nonce",
            "verified": True,
            "signable": True,
            "source_ids": ["technocore-readme-82d94293"],
        },
    )
    # We only test the suffix helper here; the underlying /candidate behavior is
    # already covered by discord_control tests.
    suffix = discord_knowledge._candidate_suffix("candidate-1")

    assert "Knowledge: nonce | verified | signed-ready" in suffix
    assert "technocore-readme-82d94293" in suffix
    assert "evil.invalid" not in suffix
    assert "@everyone" not in suffix


def test_ack_audit_sync_failure_never_breaks_discord_notices(monkeypatch):
    control = discord_knowledge.Control({"42"}, "99")
    monkeypatch.setattr(discord_knowledge.base.Control, "system_notices", lambda _self: ["base-notice"])
    monkeypatch.setattr(knowledge, "sync_acknowledged_usage", lambda: (_ for _ in ()).throw(RuntimeError("audit unavailable")))
    monkeypatch.setattr(discord_knowledge, "_LAST_AUDIT_SYNC", 0.0)

    assert control.system_notices() == ["base-notice"]


def test_production_discord_service_uses_knowledge_wrapper():
    from pathlib import Path

    service = Path("packaging/oracle/discord.service").read_text("utf-8")

    assert "-m flop_agent.discord_knowledge" in service
    assert "oracle_signer" not in service
