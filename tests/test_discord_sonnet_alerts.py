import json

import httpx
import pytest

from flop_agent import core, discord_sonnet_alerts as alerts


def row(
    identifier,
    text,
    *,
    association="MEMBER",
    login="operator",
    created="2026-09-14T00:00:00Z",
):
    return {
        "id": identifier,
        "created_at": created,
        "updated_at": created,
        "body": text,
        "author_association": association,
        "user": {"login": login},
    }


def configure(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    monkeypatch.setattr(alerts.resident, "resident_dir", lambda: tmp_path / "resident")
    monkeypatch.setattr(alerts, "PROCESS_STARTED_AT", 1000.0)
    (tmp_path / "resident").mkdir()


def empty_rooms(_room, _since=None):
    return []


def signed_invite(seq, request_id="maru-invite-lon-20260914-1", *, ts="1970-01-01T00:00:01Z"):
    return {
        "from": alerts.INVITED_DIDS[request_id],
        "nonce": str(seq),
        "sig": "A" * 86,
        "seq": seq,
        "ts": ts,
        "text": (
            '{"type":"sonnet.invite-response.v1","contest_id":"sonnet-2",'
            f'"request_id":"{request_id}"'
            "}"
        ),
    }


def test_initial_history_baselines_then_new_event_and_restart_dedupes(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    historical = row(1, "MARU writer team disposition", created="1970-01-01T00:00:01Z")
    fresh = row(2, "MARU writer team disposition", created="1970-01-01T00:16:41Z")
    assert alerts.poll_notices(now=1000, fetch=lambda i: [historical] if i == 25 else [], room_read=empty_rooms) == []
    notices = alerts.poll_notices(now=1301, fetch=lambda i: [historical, fresh] if i == 25 else [], room_read=empty_rooms)
    assert len(notices) == 1
    assert alerts.poll_notices(now=1602, fetch=lambda i: [historical, fresh] if i == 25 else [], room_read=empty_rooms) == []


def test_source_that_failed_first_poll_baselines_on_its_first_success(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    historical = row(7, "MARU writer disposition", created="1970-01-01T00:00:01Z")
    newer = row(8, "MARU writer disposition", created="1970-01-01T00:30:00Z")
    first = {"value": True}

    def fetch(issue):
        if issue == 16 and first["value"]:
            raise httpx.TimeoutException("x")
        if issue == 16:
            return [historical]
        return []

    assert alerts.poll_notices(now=1000, fetch=fetch, room_read=empty_rooms) == []
    first["value"] = False
    assert alerts.poll_notices(now=1301, fetch=fetch, room_read=empty_rooms) == []
    assert len(alerts.poll_notices(now=1602, fetch=lambda i: [historical, newer] if i == 16 else [], room_read=empty_rooms)) == 1


def test_sv_contributor_is_official_but_other_contributor_is_not():
    text = "MARU writer team disposition"
    assert alerts._github_relevant(25, row(1, text, association="CONTRIBUTOR", login="sv"))
    assert alerts._github_relevant(25, row(2, text, association="CONTRIBUTOR", login="random")) is None


def test_room_evidence_is_signed_and_never_calls_reply_consent(monkeypatch):
    monkeypatch.setattr(alerts, "verify_signed_record", lambda *_a: None)
    invite = signed_invite(1)
    team = {
        "from": alerts.REFEREE_DID,
        "nonce": "2",
        "sig": "A" * 86,
        "seq": 2,
        "ts": "1970-01-01T00:00:02Z",
        "text": (
            '{"contest_id":"sonnet-2","game_id":"maru73s2",'
            '"poem_room":"d-sonnet-2-team-maru73s2",'
            '"type":"sonnet.setup.v1","room_generation":1}'
        ),
    }
    values = alerts._public_evidence([(alerts.DISCOVERY_ROOM, invite), (alerts.RESULTS_ROOM, team)])
    assert len(values) == 2
    assert "consent" in values[0][2][1]
    assert "generation/setup" in values[1][2][0]
    original_invite = dict(invite)
    original_invite["text"] = original_invite["text"].replace("invite-response", "note")
    assert alerts._public_evidence([(alerts.DISCOVERY_ROOM, original_invite)]) == []
    bad = dict(team)
    bad["from"] = "did:key:z6Mkother"
    assert len(alerts._public_evidence([(alerts.RESULTS_ROOM, bad)])) == 0
    wrong = dict(invite)
    wrong["from"] = alerts.INVITED_DIDS["maru-invite-fuego-20260914-1"]
    assert alerts._public_evidence([(alerts.DISCOVERY_ROOM, wrong)]) == []


def test_full_history_high_water_does_not_replay(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    events = [row(i, "MARU writer team disposition", created="1970-01-01T00:00:00Z") for i in range(300)]
    assert alerts.poll_notices(now=1000, fetch=lambda i: events if i == 25 else [], room_read=empty_rooms) == []
    assert alerts.poll_notices(now=1301, fetch=lambda i: events if i == 25 else [], room_read=empty_rooms) == []
    newer = row(999, "MARU writer team disposition", created="1970-01-01T00:22:00Z")
    assert len(alerts.poll_notices(now=1602, fetch=lambda i: [*events, newer] if i == 25 else [], room_read=empty_rooms)) == 1
    assert alerts.poll_notices(now=1903, fetch=lambda i: [*events, newer] if i == 25 else [], room_read=empty_rooms) == []


def test_room_cursor_uses_since_and_failed_initial_room_does_not_replay(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    monkeypatch.setattr(alerts, "verify_signed_record", lambda *_a: None)
    calls = []
    fail_discovery = {"value": True}
    historical = signed_invite(10, ts="1970-01-01T00:00:01Z")
    newer = signed_invite(11, ts="1970-01-01T00:30:00Z")

    def room_read(room, since=None):
        calls.append((room, since))
        if room == alerts.DISCOVERY_ROOM and fail_discovery["value"]:
            raise httpx.TimeoutException("x")
        if room == alerts.DISCOVERY_ROOM:
            return [historical] if since is None else ([newer] if since == 10 else [])
        return []

    assert alerts.poll_notices(now=1000, fetch=lambda _i: [], room_read=room_read) == []
    fail_discovery["value"] = False
    assert alerts.poll_notices(now=1301, fetch=lambda _i: [], room_read=room_read) == []
    notices = alerts.poll_notices(now=1602, fetch=lambda _i: [], room_read=room_read)
    assert len(notices) == 1
    assert (alerts.DISCOVERY_ROOM, None) in calls
    assert (alerts.DISCOVERY_ROOM, 10) in calls


def test_room_rows_recovers_newest_limit_gap_from_export(monkeypatch):
    live = {"messages": [{"seq": 5, "text": "x"}, {"seq": 6, "text": "y"}]}
    monkeypatch.setattr(core, "read_room", lambda *_a, **_k: live)
    export_rows = [{"seq": seq, "text": str(seq)} for seq in range(2, 7)]

    class Response:
        text = "\n".join(json.dumps(item) for item in export_rows)
        def raise_for_status(self):
            return None

    monkeypatch.setattr(alerts.httpx, "get", lambda *_a, **_k: Response())
    rows = alerts._room_rows(alerts.DISCOVERY_ROOM, 1)
    assert [item["seq"] for item in rows] == [2, 3, 4, 5, 6]


def test_unrecoverable_room_gap_emits_one_fail_closed_notice(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    state = alerts._default()
    state["rooms"][alerts.DISCOVERY_ROOM] = {"initialized": True, "seq": 1}
    alerts._save(state)
    retained = [signed_invite(3), signed_invite(4)]

    def room_read(room, since=None):
        if room == alerts.DISCOVERY_ROOM:
            raise alerts.RoomRetentionGap(room, 2, 2, retained)
        return []

    monkeypatch.setattr(alerts, "verify_signed_record", lambda *_a: None)
    notices = alerts.poll_notices(now=1000, fetch=lambda _i: [], room_read=room_read)
    assert any("監視ギャップ" in notice for notice in notices)
    saved = alerts._load()
    assert saved["rooms"][alerts.DISCOVERY_ROOM]["seq"] == 4
    assert alerts.poll_notices(now=1301, fetch=lambda _i: [], room_read=lambda *_a: []) == []


def test_more_than_four_notices_are_delivered_from_pending_without_loss(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    state = alerts._default()
    state["github"]["gh:25"] = {"initialized": True, "max_id": 0, "max_updated_at": ""}
    for issue in (16, 22):
        state["github"][f"gh:{issue}"] = {"initialized": True, "max_id": 0, "max_updated_at": ""}
    state["rooms"][alerts.DISCOVERY_ROOM] = {"initialized": True, "seq": 0}
    state["rooms"][alerts.RESULTS_ROOM] = {"initialized": True, "seq": 0}
    alerts._save(state)
    events = [row(i, "MARU writer team disposition", created=f"1970-01-01T00:20:{i:02d}Z") for i in range(1, 6)]
    first = alerts.poll_notices(now=1301, fetch=lambda i: events if i == 25 else [], room_read=empty_rooms)
    second = alerts.poll_notices(now=1302, fetch=lambda _i: [], room_read=empty_rooms)
    assert len(first) == 4
    assert len(second) == 1


def test_timeout_rate_limit_and_irrelevant_are_safe(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    assert alerts.poll_notices(now=1000, fetch=lambda _i: (_ for _ in ()).throw(httpx.TimeoutException("x")), room_read=empty_rooms) == []
    assert alerts.poll_notices(now=1100, fetch=lambda _i: (_ for _ in ()).throw(httpx.HTTPStatusError("x", request=httpx.Request("GET", "https://x"), response=httpx.Response(429))), room_read=empty_rooms) == []
    assert alerts._github_relevant(25, row(1, "unrelated", association="NONE")) is None


def test_asad_lane_is_self_contained_and_source_is_get_only():
    assert alerts._github_relevant(22, row(1, "Asad writer role resolution", association="MEMBER"))
    source = (core.ROOT / "src" / "flop_agent" / "discord_sonnet_alerts.py").read_text("utf-8")
    assert "httpx.post" not in source
    assert "oracle_signer" not in source
    assert "invoke_signer" not in source
