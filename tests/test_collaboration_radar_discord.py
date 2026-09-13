from flop_agent import collaboration_radar as radar
from flop_agent import discord_collaboration


def _row():
    return radar.RequestMatch(
        request_id="req1",
        requester_fingerprint="requester123",
        requester_did="did:key:z6MkRequester",
        topic="repo_tests_bugs",
        summary="Please review [URL] and validate the repo test",
        room="lobby",
        seq=12,
        permalink="https://technocore.chat/humans#r/lobby/12",
        created_at="2026-09-13T01:00:00+00:00",
        external_reference_present=True,
        smallest_next_step="Ask for one bounded public reproduction or validation result.",
        matches=(
            radar.Match(
                fingerprint="capable123",
                did="did:key:z6MkCapable",
                score=9,
                confidence="high",
                reasons=("observed technical indicators: python, test",),
                evidence_refs=(
                    "candidate:proof1:https://technocore.chat/humans#r/dev-room/40",
                ),
            ),
        ),
    )


def test_radar_command_is_authorized_bounded_read_only(monkeypatch):
    monkeypatch.setattr(discord_collaboration.collaboration_radar, "scan", lambda **_kwargs: [_row()])
    control = discord_collaboration.Control({"42"}, "99")

    denied = control.command("7", "/radar", "99")
    result = control.command("42", "/radar", "99")

    assert denied["ok"] is False
    assert result["ok"] is True
    assert "Collaboration Radar — read-only" in result["message"]
    assert "capable" in result["message"]
    assert "外部URLを含みます。Radarは開いていません" in result["message"]
    assert "接触・署名・投稿・URLアクセスをしません" in result["message"]


def test_radar_command_rejects_extra_arguments():
    control = discord_collaboration.Control({"42"}, "99")

    result = control.command("42", "/radar now", "99")

    assert result == {"ok": False, "error": "invalid_args", "message": "Usage: /radar"}
