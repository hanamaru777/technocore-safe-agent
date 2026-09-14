import httpx

from flop_agent import core, discord_sonnet_alerts as alerts


def row(identifier, text, *, association="MEMBER", login="operator", created="2026-09-14T00:00:00Z"):
    return {"id": identifier, "created_at": created, "updated_at": created, "body": text, "author_association": association, "user": {"login": login}}


def configure(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    monkeypatch.setattr(alerts.resident, "resident_dir", lambda: tmp_path / "resident")
    (tmp_path / "resident").mkdir()


def empty_rooms(_room): return []


def test_initial_history_baselines_then_new_event_and_restart_dedupes(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    historical = row(1, "MARU writer team disposition", created="1970-01-01T00:00:01Z")
    fresh = row(2, "MARU writer team disposition", created="1970-01-01T00:16:41Z")
    assert alerts.poll_notices(now=1000, fetch=lambda i: [historical] if i == 25 else [], room_read=empty_rooms) == []
    notices = alerts.poll_notices(now=1301, fetch=lambda i: [historical, fresh] if i == 25 else [], room_read=empty_rooms)
    assert len(notices) == 1
    assert alerts.poll_notices(now=1602, fetch=lambda i: [historical, fresh] if i == 25 else [], room_read=empty_rooms) == []


def test_sv_contributor_is_official_but_other_contributor_is_not():
    text = "MARU writer team disposition"
    assert alerts._github_relevant(25, row(1, text, association="CONTRIBUTOR", login="sv"))
    assert alerts._github_relevant(25, row(2, text, association="CONTRIBUTOR", login="random")) is None


def test_room_evidence_is_signed_and_never_calls_reply_consent(monkeypatch):
    monkeypatch.setattr(alerts, "verify_signed_record", lambda *_a: None)
    invite = {"from": "did:key:z6Mtest", "nonce": "1", "text": '{"type":"sonnet.invite-response.v1","contest_id":"sonnet-2","request_id":"maru-invite-lon-20260914-1"}'}
    team = {"from": "did:key:z6Mtest", "nonce": "2", "text": '{"contest_id":"sonnet-2","game_id":"maru73s2","poem_room":"d-sonnet-2-team-maru73s2","type":"sonnet.team-setup-receipt.v1","referee_receipt":"proof"}'}
    values = alerts._public_evidence([(alerts.DISCOVERY_ROOM, invite), (alerts.TEAM_ROOM, team)])
    assert len(values) == 2 and "consent" in values[0][2][1] and "generation/setup" in values[1][2][0]
    original_invite = dict(invite); original_invite["text"] = original_invite["text"].replace("invite-response", "note")
    assert alerts._public_evidence([(alerts.DISCOVERY_ROOM, original_invite)]) == []
    bad = dict(team); bad["text"] = bad["text"].replace("referee_receipt", "untrusted_receipt")
    assert len(alerts._public_evidence([(alerts.TEAM_ROOM, bad)])) == 0


def test_ordered_bounded_dedupe_does_not_realert_retained_latest(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path); monkeypatch.setattr(alerts, "SEEN_LIMIT", 3)
    state = {"schema_version": 2, "initialized": True, "seen": [], "next_poll_at": 0, "failures": 0}; alerts._save(state)
    events = [row(i, "MARU writer team disposition", created="1970-01-01T00:00:00Z") for i in range(5)]
    assert len(alerts.poll_notices(now=1000, fetch=lambda i: events if i == 25 else [], room_read=empty_rooms)) == 4
    assert alerts.poll_notices(now=1301, fetch=lambda i: events[-3:] if i == 25 else [], room_read=empty_rooms) == []


def test_timeout_rate_limit_and_irrelevant_are_safe(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    assert alerts.poll_notices(now=1000, fetch=lambda _i: (_ for _ in ()).throw(httpx.TimeoutException("x")), room_read=empty_rooms) == []
    assert alerts.poll_notices(now=1100, fetch=lambda _i: (_ for _ in ()).throw(httpx.HTTPStatusError("x", request=httpx.Request("GET", "https://x"), response=httpx.Response(429))), room_read=empty_rooms) == []
    assert alerts._github_relevant(25, row(1, "unrelated", association="NONE")) is None


def test_asad_lane_is_self_contained_and_source_is_get_only():
    assert alerts._github_relevant(22, row(1, "Asad writer role resolution", association="MEMBER"))
    source = (core.ROOT / "src" / "flop_agent" / "discord_sonnet_alerts.py").read_text("utf-8")
    assert "httpx.post" not in source and "oracle_signer" not in source and "invoke_signer" not in source
