import base64
import json
import os
import sys
from contextlib import nullcontext
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from flop_agent import core, oracle_signer, public_record, sonnet_discovery_invites as lane


@pytest.fixture
def environment(monkeypatch, tmp_path):
    key = Ed25519PrivateKey.generate()
    number = int.from_bytes(b"\xed\x01" + key.public_key().public_bytes_raw(), "big")
    encoded = ""
    while number:
        number, rem = divmod(number, 58)
        encoded = public_record.B58[rem] + encoded
    did = "did:key:z" + encoded
    monkeypatch.setattr(lane, "DID", did)
    monkeypatch.setattr(core, "STATE", tmp_path)
    (tmp_path / "signer").mkdir()
    monkeypatch.setattr(lane, "invite_lock", nullcontext)
    monkeypatch.setattr(lane, "require_identity", lambda: None)
    monkeypatch.setattr(lane, "require_health", lambda: None)
    monkeypatch.setattr(lane, "require_registration_posted", lambda: None)
    monkeypatch.setattr(core, "git_commit_sha", lambda: "a" * 40)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 9, 12, 12, tzinfo=UTC)

    monkeypatch.setattr(lane, "datetime", Clock)
    rows, posts, signs, buffers = [], [], [], []

    def read(room, **kwargs):
        assert room == lane.ROOM
        assert kwargs["limit"] == 200 and kwargs["cache_buster"]
        return {"messages": rows}

    monkeypatch.setattr(core, "read_room", read)

    def vault():
        value = bytearray(key.private_bytes_raw().hex().encode())
        buffers.append(value)
        return value

    monkeypatch.setattr(oracle_signer, "vault_seed", vault)

    def sign(*args):
        assert args[0] == "say" and args[1] == lane.ROOM
        assert os.environ.pop("SIGN_SEED") == key.private_bytes_raw().hex()
        signs.append(args)
        signature = key.sign("|".join(args[1:]).encode())
        return [did, base64.urlsafe_b64encode(signature).decode().rstrip("=")]

    monkeypatch.setattr(core, "invoke_signer", sign)

    seq = {"value": 100}

    def record(text, nonce):
        seq["value"] += 1
        return {
            "from": did,
            "nonce": nonce,
            "text": text,
            "seq": seq["value"],
            "ts": Clock.now().isoformat(),
            "sig": base64.urlsafe_b64encode(
                key.sign(f"{lane.ROOM}|{nonce}|{text}".encode())
            ).decode().rstrip("="),
        }

    def post(url, *, json, timeout):
        assert url == f"{core.BASE_URL}/r/{lane.ROOM}?format=json"
        note = __import__("json").loads(json["text"])
        assert lane.load()["entries"][note["request_id"]]["state"] == "attempting"
        assert "SIGN_SEED" not in os.environ
        posts.append(json)
        row = record(json["text"], json["nonce"])
        rows.append(row)
        return core.httpx.Response(
            200,
            json={"posted": row},
            request=core.httpx.Request("POST", url),
        )

    monkeypatch.setattr(core.httpx, "post", post)
    return rows, posts, signs, buffers, record


def test_exact_three_fixed_invitations_post_once(environment):
    _, posts, signs, buffers, _ = environment
    result = lane.run_once()
    assert result["status"] == "complete"
    assert len(posts) == len(signs) == 3
    assert [json.loads(item["text"]) for item in posts] == list(lane.INVITATIONS)
    assert all(not any(buf) for buf in buffers)
    assert "SIGN_SEED" not in os.environ

    second = lane.run_once()
    assert second["status"] == "complete"
    assert len(posts) == len(signs) == 3
    assert all(item["action"] == "already_posted" for item in second["actions"])


@pytest.mark.parametrize(
    "field,value",
    [
        ("type", "other"),
        ("contest_id", "sonnet-1"),
        ("target_did", "did:key:z6Mk" + "1" * 44),
        ("request_id", "other"),
        ("text", "arbitrary text"),
    ],
)
def test_binding_rejects_any_mutation(field, value):
    note = dict(lane.INVITATIONS[0])
    note[field] = value
    with pytest.raises(lane.InviteError, match="invite_binding_invalid"):
        lane.render(note)


def test_wrong_room_and_cli_args_rejected(monkeypatch):
    with pytest.raises(lane.InviteError):
        lane.render(dict(lane.INVITATIONS[0]), "lobby")
    monkeypatch.setattr(sys, "argv", ["sonnet_discovery_invites", "extra"])
    monkeypatch.setattr(lane, "run_once", lambda: pytest.fail("must not execute"))
    with pytest.raises(SystemExit):
        lane.main()


def test_health_failure_blocks_before_sign_or_post(environment, monkeypatch):
    _, posts, signs, _, _ = environment
    monkeypatch.setattr(
        lane,
        "require_health",
        lambda: (_ for _ in ()).throw(lane.InviteError("observer_health_not_ok")),
    )
    with pytest.raises(lane.InviteError, match="observer_health_not_ok"):
        lane.run_once()
    assert posts == signs == []


def test_registration_gate_blocks_before_sign_or_post(environment, monkeypatch):
    _, posts, signs, _, _ = environment
    monkeypatch.setattr(
        lane,
        "require_registration_posted",
        lambda: (_ for _ in ()).throw(lane.InviteError("writer_registration_not_posted")),
    )
    with pytest.raises(lane.InviteError, match="writer_registration_not_posted"):
        lane.run_once()
    assert posts == signs == []


def test_second_post_ambiguity_is_terminal_and_third_is_not_sent(environment, monkeypatch):
    _, posts, signs, _, _ = environment
    original = core.httpx.post
    count = {"value": 0}

    def fail_second(*args, **kwargs):
        count["value"] += 1
        if count["value"] == 2:
            posts.append(kwargs["json"])
            raise core.httpx.ConnectTimeout("dummy")
        return original(*args, **kwargs)

    monkeypatch.setattr(core.httpx, "post", fail_second)
    with pytest.raises(lane.InviteError, match="submission_unknown"):
        lane.run_once()
    state = lane.load()
    ids = [item["request_id"] for item in lane.INVITATIONS]
    assert state["entries"][ids[0]]["state"] == "posted"
    assert state["entries"][ids[1]]["state"] == "ambiguous"
    assert state["entries"][ids[2]]["state"] == "new"
    before_posts, before_signs = len(posts), len(signs)
    result = lane.run_once()
    assert result["status"] == "ambiguous"
    assert len(posts) == before_posts and len(signs) == before_signs


def test_ambiguous_exact_readback_reconciles_then_finishes(environment, monkeypatch):
    rows, posts, signs, _, record = environment
    original = core.httpx.post
    count = {"value": 0}

    def fail_second(*args, **kwargs):
        count["value"] += 1
        if count["value"] == 2:
            posts.append(kwargs["json"])
            raise core.httpx.ConnectTimeout("dummy")
        return original(*args, **kwargs)

    monkeypatch.setattr(core.httpx, "post", fail_second)
    with pytest.raises(lane.InviteError):
        lane.run_once()
    state = lane.load()
    second = lane.INVITATIONS[1]["request_id"]
    entry = state["entries"][second]
    rows.append(record(lane.render(entry["payload"]), entry["nonce"]))
    monkeypatch.setattr(core.httpx, "post", original)
    result = lane.run_once()
    assert result["status"] == "complete"
    assert lane.load()["entries"][second]["state"] == "posted"
    assert len(posts) == 3
    assert len(signs) == 3


def test_conflicting_existing_same_request_id_fails_closed(environment):
    rows, posts, signs, _, record = environment
    note = dict(lane.INVITATIONS[0])
    note["text"] = "changed"
    text = json.dumps(note, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    rows.append(record(text, "123"))
    with pytest.raises(lane.InviteError, match="existing_invite_conflict"):
        lane.run_once()
    assert posts == signs == []


def test_error_output_never_leaks_exception(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["sonnet_discovery_invites"])
    monkeypatch.setattr(
        lane,
        "run_once",
        lambda: (_ for _ in ()).throw(RuntimeError("dummy sensitive material")),
    )
    with pytest.raises(SystemExit):
        lane.main()
    assert json.loads(capsys.readouterr().out) == {
        "ok": False,
        "error": "invitation_failed_closed",
    }


def test_one_shot_unit_preserves_isolation_and_cannot_auto_start():
    text = (
        core.ROOT
        / "packaging/oracle/technocore-safe-agent-sonnet-invites.service"
    ).read_text("utf-8")
    for required in (
        "Type=oneshot",
        "User=technocore-signer",
        "Group=technocore-signer",
        "SupplementaryGroups=technocore-autopilot",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "-m flop_agent.sonnet_discovery_invites",
    ):
        assert required in text
    for forbidden in (
        "[Install]",
        "Restart=",
        "SupplementaryGroups=technocore\n",
        "/etc/technocore-safe-agent/env",
        "autopilot /",
    ):
        assert forbidden not in text
