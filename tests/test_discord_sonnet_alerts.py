import json

import httpx

from flop_agent import core, discord_sonnet_alerts as alerts


def row(identifier, text, association="MEMBER"):
    return {"id": identifier, "updated_at": "2026-09-14T00:00:00Z", "body": text, "author_association": association}


def configure(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    monkeypatch.setattr(alerts.resident, "resident_dir", lambda: tmp_path / "resident")
    (tmp_path / "resident").mkdir()


def test_relevant_official_maru_update_once_and_restart_dedupes(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    fetch = lambda issue: [row(1, "MARU writer team disposition accepted for maru73s2")] if issue == 25 else []
    first = alerts.poll_notices(now=1000, fetch=fetch)
    assert len(first) == 1 and "MARU official disposition" in first[0]
    assert alerts.poll_notices(now=1400, fetch=fetch) == []


def test_irrelevant_and_untrusted_comment_never_notifies(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    fetch = lambda issue: [row(1, "MARU writer team", "NONE"), row(2, "unrelated discussion", "MEMBER")] if issue == 25 else []
    assert alerts.poll_notices(now=1000, fetch=fetch) == []


def test_timeout_and_rate_limit_backoff_no_notice_or_write(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    writes = []
    monkeypatch.setattr(alerts, "_save", lambda state: writes.append(dict(state)))
    for error in (httpx.TimeoutException("x"), httpx.HTTPStatusError("x", request=httpx.Request("GET", "https://x"), response=httpx.Response(429))):
        assert alerts.poll_notices(now=1000 + len(writes) * 100, fetch=lambda _issue, error=error: (_ for _ in ()).throw(error)) == []
    assert writes and writes[-1]["failures"] >= 1


def test_authoritative_team_room_and_sanitize(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    fetch = lambda issue: [row(1, "MARU maru73s2 setup team room <@123> https://bad.invalid/x")] if issue == 25 else []
    notice = alerts.poll_notices(now=1000, fetch=fetch)[0]
    assert "team-room setup" in notice and "[URL省略]" in notice and "<@123>" not in notice


def test_invite_reply_is_not_roster_consent():
    result = alerts._relevant(25, row(1, "maru-invite-lon-20260914-1 reply received", "MEMBER"))
    assert result and "invitation" in result[0] and "consent" in result[1]


def test_source_is_fixed_get_only():
    source = (core.ROOT / "src" / "flop_agent" / "discord_sonnet_alerts.py").read_text("utf-8")
    assert "api.github.com/repos/{REPO}/issues/{issue}/comments" in source
    assert "httpx.post" not in source and "oracle_signer" not in source and "invoke_signer" not in source
