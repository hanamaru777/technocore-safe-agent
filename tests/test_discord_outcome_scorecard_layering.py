from flop_agent import discord_outcome_scorecard as score


def test_activity_renderer_leaves_collaboration_pipeline_to_existing_overlay(monkeypatch):
    activity = {
        "snapshot": {
            "health": "ok",
            "auto": {"queued": 0},
        },
        "posts": 1,
        "reasons": {},
        "zero_reason": None,
        "interactions": [],
        "signed_direct_requests": 2,
        "acked_replies": 1,
        "counterparts": 2,
        "active_trusted": 1,
        "collaboration_active": 4,
        "collaboration_completed": 3,
        "public_artifacts": 1,
        "oldest_unresolved_direct": None,
    }
    monkeypatch.setattr(score, "_activity_snapshot", lambda **_kwargs: activity)

    rendered = score._activity_message()

    assert "関係24h: 署名direct 2 / ACK返信 1 / ユニーク相手 2人" in rendered
    assert "active trust: 1" in rendered
    assert "継続成果:" not in rendered
    assert "協業進行" not in rendered
    assert "協業完了" not in rendered
