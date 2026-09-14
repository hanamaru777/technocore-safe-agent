import json

import httpx

from flop_agent import core, discord_sonnet_alerts as alerts


def row(
    identifier,
    text,
    *,
    association="MEMBER",
    login="operator",
    created="2026-09-14T00:00:00Z",
    updated=None,
):
    stamp = updated or created
    return {
        "id": identifier,
        "created_at": created,
        "updated_at": stamp,
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


def signed_activity(
    seq=None,
    request_id="maru-invite-lon-20260914-1",
    *,
    ts="1970-01-01T00:30:00Z",
    text=None,
):
    meta = alerts.INVITATIONS[request_id]
    actual_seq = meta["sent_seq"] + 1 if seq is None else seq
    if text is None:
        text = json.dumps(
            {
                "type": "sonnet.note.v1",
                "contest_id": "sonnet-2",
                "target_did": alerts.MARU_DID,
                "text": "interested",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    return {
        "from": meta["did"],
        "nonce": str(actual_seq),
        "sig": "A" * 86,
        "seq": actual_seq,
        "ts": ts,
        "text": text,
    }


def test_initial_history_baselines_then_new_event_and_restart_dedupes(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    historical = row(1, "maintainer triage", created="1970-01-01T00:00:01Z")
    fresh = row(2, "accepted writer disposition", created="1970-01-01T00:16:41Z")
    assert alerts.poll_notices(now=1000, fetch=lambda i: [historical] if i == 25 else [], room_read=empty_rooms) == []
    assert len(alerts.poll_notices(now=1301, fetch=lambda i: [historical, fresh] if i == 25 else [], room_read=empty_rooms)) == 1
    assert alerts.poll_notices(now=1602, fetch=lambda i: [historical, fresh] if i == 25 else [], room_read=empty_rooms) == []


def test_corrupt_state_rebaselines_without_replay_then_allows_new_event(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    clock = {"value": 2000.0}
    monkeypatch.setattr(alerts.time, "time", lambda: clock["value"])
    alerts.state_path().write_text("{broken", encoding="utf-8")
    historical = row(7, "authoritative result", created="1970-01-01T00:25:00Z")
    assert alerts.poll_notices(now=2000, fetch=lambda i: [historical] if i == 25 else [], room_read=empty_rooms) == []
    clock["value"] = 2301.0
    newer = row(8, "new authoritative result", created="1970-01-01T00:35:00Z")
    assert len(alerts.poll_notices(now=2301, fetch=lambda i: [historical, newer] if i == 25 else [], room_read=empty_rooms)) == 1
    assert alerts.poll_notices(now=2602, fetch=lambda i: [historical, newer] if i == 25 else [], room_read=empty_rooms) == []


def test_multiple_new_github_rows_in_one_poll_are_all_notified(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    state = alerts._default()
    state["github"]["gh:25"] = {"initialized": True, "max_id": 10, "max_updated_at": "1970-01-01T00:10:00Z"}
    alerts._save(state)
    newer_a = row(12, "first authoritative reply", created="1970-01-01T00:20:00Z")
    newer_b = row(11, "second authoritative reply", created="1970-01-01T00:19:00Z")
    notices = alerts.poll_notices(now=1301, fetch=lambda i: [newer_a, newer_b] if i == 25 else [], room_read=empty_rooms)
    assert len(notices) == 2


def test_source_that_failed_first_poll_baselines_on_its_first_success(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    historical = row(7, f"{alerts.MARU_DID} writer registration", created="1970-01-01T00:00:01Z")
    newer = row(8, f"{alerts.MARU_DID} writer registration accepted", created="1970-01-01T00:30:00Z")
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
    assert alerts._github_relevant(25, row(1, "authoritative reply", association="CONTRIBUTOR", login="sv"))
    assert alerts._github_relevant(25, row(2, "fake reply", association="CONTRIBUTOR", login="random")) is None


def test_issue_16_matches_exact_maru_identifiers():
    assert alerts._github_relevant(16, row(1, f"{alerts.MARU_DID} writer registration accepted"))
    assert alerts._github_relevant(16, row(2, f"{alerts.MARU_REGISTRATION_REQUEST_ID} disposition accepted"))


def test_invited_writer_activity_requires_exact_sender_target_and_post_invite_seq(monkeypatch):
    monkeypatch.setattr(alerts, "verify_signed_record", lambda *_a: None)
    rid = "maru-invite-lon-20260914-1"
    sent_seq = alerts.INVITATIONS[rid]["sent_seq"]
    before = signed_activity(seq=sent_seq, request_id=rid)
    after = signed_activity(seq=sent_seq + 1, request_id=rid)
    unrelated = signed_activity(seq=sent_seq + 2, request_id=rid, text='{"type":"sonnet.note.v1","contest_id":"sonnet-2","target_did":"did:key:z6MkSomebodyElse123456789ABCDEFGHJKLMNPQ","text":"hello"}')
    values = alerts._public_evidence([
        (alerts.DISCOVERY_ROOM, before),
        (alerts.DISCOVERY_ROOM, after),
        (alerts.DISCOVERY_ROOM, unrelated),
    ])
    assert len(values) == 1
    assert "roster consent" in values[0][2][1]
    assert "MARU宛てactivity" in values[0][2][0]
    wrong = dict(after)
    wrong["from"] = "did:key:z6MknotInvitedWriter123456789ABCDEFGHJKLMNPQ"
    assert alerts._public_evidence([(alerts.DISCOVERY_ROOM, wrong)]) == []


def test_plain_text_candidate_mention_of_maru_is_detected(monkeypatch):
    monkeypatch.setattr(alerts, "verify_signed_record", lambda *_a: None)
    rid = "maru-invite-fuego-20260914-1"
    message = signed_activity(
        request_id=rid,
        text="MinerMaru73 yes, I saw your sonnet-2 invitation.",
    )
    assert len(alerts._public_evidence([(alerts.DISCOVERY_ROOM, message)])) == 1


def test_team_setup_requires_exact_referee_game_room_and_generation(monkeypatch):
    monkeypatch.setattr(alerts, "verify_signed_record", lambda *_a: None)
    team = {
        "from": alerts.REFEREE_DID,
        "nonce": "2",
        "sig": "A" * 86,
        "seq": 2,
        "ts": "1970-01-01T00:00:02Z",
        "text": '{"contest_id":"sonnet-2","game_id":"maru73s2","poem_room":"d-sonnet-2-team-maru73s2","type":"sonnet.setup.v1","room_generation":1}',
    }
    values = alerts._public_evidence([(alerts.RESULTS_ROOM, team)])
    assert len(values) == 1 and "generation/setup" in values[0][2][0]
    bad = dict(team)
    bad["from"] = "did:key:z6Mkother"
    assert alerts._public_evidence([(alerts.RESULTS_ROOM, bad)]) == []
    wrong_room = dict(team)
    wrong_room["text"] = wrong_room["text"].replace("d-sonnet-2-team-maru73s2", "d-sonnet-2-team-other")
    assert alerts._public_evidence([(alerts.RESULTS_ROOM, wrong_room)]) == []


def test_full_history_high_water_does_not_replay(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    events = [row(i, "authoritative reply", created="1970-01-01T00:00:00Z") for i in range(300)]
    assert alerts.poll_notices(now=1000, fetch=lambda i: events if i == 25 else [], room_read=empty_rooms) == []
    assert alerts.poll_notices(now=1301, fetch=lambda i: events if i == 25 else [], room_read=empty_rooms) == []
    newer = row(999, "new authoritative reply", created="1970-01-01T00:22:00Z")
    assert len(alerts.poll_notices(now=1602, fetch=lambda i: [*events, newer] if i == 25 else [], room_read=empty_rooms)) == 1
    assert alerts.poll_notices(now=1903, fetch=lambda i: [*events, newer] if i == 25 else [], room_read=empty_rooms) == []


def test_room_cursor_uses_since_and_failed_initial_room_does_not_replay(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    monkeypatch.setattr(alerts, "verify_signed_record", lambda *_a: None)
    calls = []
    fail_discovery = {"value": True}
    rid = "maru-invite-lon-20260914-1"
    historical = signed_activity(request_id=rid, ts="1970-01-01T00:00:01Z")
    newer = signed_activity(seq=historical["seq"] + 1, request_id=rid, ts="1970-01-01T00:30:00Z")

    def room_read(room, since=None):
        calls.append((room, since))
        if room == alerts.DISCOVERY_ROOM and fail_discovery["value"]:
            raise httpx.TimeoutException("x")
        if room == alerts.DISCOVERY_ROOM:
            if since is None:
                return [historical]
            if since == historical["seq"]:
                return [newer]
        return []

    assert alerts.poll_notices(now=1000, fetch=lambda _i: [], room_read=room_read) == []
    fail_discovery["value"] = False
    assert alerts.poll_notices(now=1301, fetch=lambda _i: [], room_read=room_read) == []
    assert len(alerts.poll_notices(now=1602, fetch=lambda _i: [], room_read=room_read)) == 1
    assert (alerts.DISCOVERY_ROOM, historical["seq"]) in calls


def test_room_rows_recovers_newest_limit_gap_from_export(monkeypatch):
    monkeypatch.setattr(core, "read_room", lambda *_a, **_k: {"messages": [{"seq": 5, "text": "x"}, {"seq": 6, "text": "y"}]})
    export_rows = [{"seq": seq, "text": str(seq)} for seq in range(2, 7)]

    class Response:
        text = "\n".join(json.dumps(item) for item in export_rows)

        def raise_for_status(self):
            return None

    monkeypatch.setattr(alerts.httpx, "get", lambda *_a, **_k: Response())
    assert [item["seq"] for item in alerts._room_rows(alerts.DISCOVERY_ROOM, 1)] == [2, 3, 4, 5, 6]


def test_unrecoverable_room_gap_emits_one_fail_closed_notice(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    rid = "maru-invite-lon-20260914-1"
    start = alerts.INVITATIONS[rid]["sent_seq"]
    state = alerts._default()
    state["rooms"][alerts.DISCOVERY_ROOM] = {"initialized": True, "seq": start}
    alerts._save(state)
    retained = [signed_activity(seq=start + 2, request_id=rid), signed_activity(seq=start + 3, request_id=rid)]

    def room_read(room, since=None):
        if room == alerts.DISCOVERY_ROOM:
            raise alerts.RoomRetentionGap(room, start + 1, start + 1, retained)
        return []

    monkeypatch.setattr(alerts, "verify_signed_record", lambda *_a: None)
    notices = alerts.poll_notices(now=1000, fetch=lambda _i: [], room_read=room_read)
    assert any("監視ギャップ" in notice for notice in notices)
    assert alerts._load()["rooms"][alerts.DISCOVERY_ROOM]["seq"] == start + 3
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
    events = [row(i, "authoritative reply", created=f"1970-01-01T00:20:{i:02d}Z") for i in range(1, 6)]
    first = alerts.poll_notices(now=1301, fetch=lambda i: events if i == 25 else [], room_read=empty_rooms)
    second = alerts.poll_notices(now=1302, fetch=lambda _i: [], room_read=empty_rooms)
    assert len(first) == 4 and len(second) == 1


def test_github_edit_notifies_once(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    base = row(10, "triage", created="1970-01-01T00:00:00Z", updated="1970-01-01T00:00:00Z")
    assert alerts.poll_notices(now=1000, fetch=lambda i: [base] if i == 25 else [], room_read=empty_rooms) == []
    edited = row(10, "accepted", created="1970-01-01T00:00:00Z", updated="1970-01-01T00:30:00Z")
    assert len(alerts.poll_notices(now=1301, fetch=lambda i: [edited] if i == 25 else [], room_read=empty_rooms)) == 1
    assert alerts.poll_notices(now=1602, fetch=lambda i: [edited] if i == 25 else [], room_read=empty_rooms) == []


def test_timeout_rate_limit_and_irrelevant_are_safe(monkeypatch, tmp_path):
    configure(monkeypatch, tmp_path)
    assert alerts.poll_notices(now=1000, fetch=lambda _i: (_ for _ in ()).throw(httpx.TimeoutException("x")), room_read=empty_rooms) == []
    assert alerts.poll_notices(now=1100, fetch=lambda _i: (_ for _ in ()).throw(httpx.HTTPStatusError("x", request=httpx.Request("GET", "https://x"), response=httpx.Response(429))), room_read=empty_rooms) == []
    assert alerts._github_relevant(25, row(1, "unrelated", association="NONE")) is None


def test_asad_lane_is_self_contained_and_source_is_get_only():
    assert alerts._github_relevant(22, row(1, "Asad organizer attribution migration resolution", association="MEMBER"))
    source = (core.ROOT / "src" / "flop_agent" / "discord_sonnet_alerts.py").read_text("utf-8")
    assert "httpx.post" not in source
    assert "oracle_signer" not in source
    assert "invoke_signer" not in source
