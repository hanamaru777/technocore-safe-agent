import ast
import inspect
from pathlib import Path

from flop_agent import discord_sonnet_outcome_overlay as overlay


def test_sonnet_event_count_uses_only_durable_notified_message_ids(monkeypatch):
    monkeypatch.setattr(
        overlay.discord_agent_activity,
        "_load",
        lambda: {
            "schema_version": 1,
            "notified": [
                "msg:mb-sonnet-2-discovery:108446",
                "msg:mb-sonnet-2-discovery:108511",
                "msg:d-sonnet-2-results:777",
                "other:event",
            ],
        },
    )
    assert overlay._sonnet_event_count() == 3


def test_relationship_line_keeps_legacy_semantics_and_adds_cockpit_count(monkeypatch):
    monkeypatch.setattr(overlay, "_ORIGINAL_RELATIONSHIP_LINE", lambda activity: "関係24h: 署名direct 0 / ACK返信 0 / ユニーク相手 0人")
    rendered = overlay._relationship_line({"sonnet_cockpit_events": 4})
    assert rendered == "関係24h: 署名direct 0 / ACK返信 0 / ユニーク相手 0人 / Sonnet重要イベント累計 4"


def test_activity_message_does_not_claim_no_interaction_when_cockpit_has_events(monkeypatch):
    monkeypatch.setattr(overlay, "_ORIGINAL_ACTIVITY_MESSAGE", lambda: "直近の直接やりとり: なし")
    monkeypatch.setattr(overlay, "_sonnet_event_count", lambda: 4)
    rendered = overlay._activity_message()
    assert "直近の直接やりとり: なし" not in rendered
    assert "Sonnet Agent重要イベント: 累計4件" in rendered


def test_digest_does_not_claim_no_interaction_when_cockpit_has_events(monkeypatch):
    monkeypatch.setattr(overlay, "_ORIGINAL_DIGEST", lambda _control: "直近の直接やりとり: なし（詳細: /history）")
    monkeypatch.setattr(overlay, "_sonnet_event_count", lambda: 3)
    rendered = overlay._digest(None)
    assert "直近の直接やりとり: なし" not in rendered
    assert "Sonnet Agent重要イベント: 累計3件" in rendered


def test_health_wrapper_lazily_installs_bridge_after_scorecard():
    source = Path("src/flop_agent/discord_health_coalescing.py").read_text("utf-8")
    assert "discord_sonnet_outcome_overlay.install()" in source
    assert source.index("discord_sonnet_outcome_overlay.install()") < source.index("discord_agent_activity.poll_notices()")


def test_overlay_has_no_network_signing_or_protocol_write_surface():
    source = inspect.getsource(overlay)
    tree = ast.parse(source)
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])
    assert imported_roots.isdisjoint({"httpx", "requests", "urllib", "socket", "subprocess"})
    assert "post_signed" not in source
    assert "invoke_signer" not in source
    assert "SIGN_SEED" not in source
    assert "/export" not in source
