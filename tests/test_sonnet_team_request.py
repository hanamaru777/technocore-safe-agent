"""Fixed team request is isolated and never blindly retries an uncertain POST."""
import base64
import hashlib
import json
import os
import sys
from contextlib import nullcontext
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from flop_agent import core, observer, oracle_signer, public_record
from flop_agent import sonnet_registration as registration
from flop_agent import sonnet_team_request as lane


@pytest.fixture
def environment(monkeypatch, tmp_path):
    # A fresh dummy key is used only for local mocked records and signatures.
    key = Ed25519PrivateKey.generate()
    number = int.from_bytes(b"\xed\x01" + key.public_key().public_bytes_raw(), "big")
    encoded = ""
    while number:
        number, rem = divmod(number, 58)
        encoded = public_record.B58[rem] + encoded
    did = "did:key:z" + encoded
    monkeypatch.setattr(lane, "DID", did)
    monkeypatch.setattr(registration, "DID", did)
    monkeypatch.setattr(core, "STATE", tmp_path)
    (tmp_path / "signer").mkdir()
    monkeypatch.setattr(lane, "team_request_lock", nullcontext)
    monkeypatch.setenv("TECHNOCORE_SIGNER_EXPECTED_DID", did)
    (tmp_path / "verified-did.json").write_text(json.dumps({"did": did}), encoding="utf-8")
    monkeypatch.setattr(core, "signer_matches_pinned", lambda: True)
    monkeypatch.setattr(core, "git_commit_sha", lambda: "a" * 40)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 9, 14, tzinfo=UTC)

    monkeypatch.setattr(lane, "datetime", Clock)
    monkeypatch.setattr(registration, "datetime", Clock)
    snapshot = {
        "schema_version": 1, "updated_at": Clock.now().isoformat(), "health": "ok",
        "unrecoverable_core_gap_events": 117,
        "unrecoverable_core_gap_messages": 5_083_155,
    }
    observer.atomic_json_write(tmp_path / "observer-safety.json", snapshot)

    def record(text, nonce="123", *, room=lane.ROOM, sender=did, seq=1):
        signature = key.sign(f"{room}|{nonce}|{text}".encode())
        return {
            "from": sender, "nonce": nonce, "text": text, "seq": seq,
            "ts": Clock.now().isoformat(),
            "sig": base64.urlsafe_b64encode(signature).decode().rstrip("="),
        }

    registration_payload = {**registration.FIXED, "request_id": "writer-registration-test"}
    reg_text = registration.render(registration_payload)
    reg_row = record(reg_text, room=registration.ROOM)
    registration.save({
        "schema_version": 1, "room": registration.ROOM, "did": did,
        "registration": registration_payload, "state": "posted", "nonce": "123",
        "text_hash": hashlib.sha256(reg_text.encode()).hexdigest(),
        "git_commit_sha": None, "attempted_at": None,
        "seq": reg_row["seq"], "ts": reg_row["ts"], "posted_record": reg_row,
    })

    rows, posts, signs = [], [], []

    def read(room, **kwargs):
        assert room == lane.ROOM and kwargs["limit"] == 200 and kwargs["cache_buster"]
        return {"messages": list(rows)}

    monkeypatch.setattr(core, "read_room", read)
    monkeypatch.setattr(oracle_signer, "with_vault_seed", lambda operation: operation())

    def sign(*args):
        assert args[0] == "say" and args[1] == lane.ROOM and args[3] == lane.render()
        signs.append(args)
        signature = key.sign("|".join(args[1:]).encode())
        return [did, base64.urlsafe_b64encode(signature).decode().rstrip("=")]

    monkeypatch.setattr(core, "invoke_signer", sign)

    def post(url, *, json, timeout):
        assert url == f"{core.BASE_URL}/r/{lane.ROOM}?format=json"
        assert lane.load()["state"] == "attempting"
        assert timeout == 20 and "SIGN_SEED" not in os.environ
        posts.append(json)
        row = record(json["text"], json["nonce"])
        rows.append(row)
        return core.httpx.Response(200, json={"posted": row}, request=core.httpx.Request("POST", url))

    monkeypatch.setattr(core.httpx, "post", post)
    return {"did": did, "key": key, "snapshot": snapshot, "rows": rows,
            "posts": posts, "signs": signs, "record": record}


def test_exact_fixed_payload_and_successful_one_post(environment):
    result = lane.run_once()
    assert result == {"action": "posted", "request_id": "maru-team-maru73s2-20260914-1", "seq": 1}
    assert json.loads(environment["posts"][0]["text"]) == lane.PAYLOAD
    assert environment["posts"][0]["text"] == lane.render()
    saved = lane.load()
    assert saved["state"] == "posted" and saved["room"] == lane.ROOM
    assert saved["did"] == environment["did"] and saved["payload"] == lane.PAYLOAD
    assert saved["text_hash"] == hashlib.sha256(lane.render().encode()).hexdigest()
    assert saved["git_commit_sha"] == "a" * 40 and saved["attempted_at"]
    assert saved["posted_record"] == environment["rows"][0]
    assert len(environment["posts"]) == len(environment["signs"]) == 1
    assert lane.run_once()["action"] == "already_posted"
    assert len(environment["posts"]) == 1


@pytest.mark.parametrize("change", [
    {"type": "sonnet.register.v1"}, {"contest_id": "sonnet-1"},
    {"game_id": "other"}, {"request_id": "other"}, {"text": "injected"},
])
def test_mutated_payload_is_rejected(change):
    with pytest.raises(lane.TeamRequestError, match="team_request_binding_invalid"):
        lane.render({**lane.PAYLOAD, **change})


def test_wrong_room_and_did_state_rejected(environment):
    with pytest.raises(lane.TeamRequestError, match="team_request_binding_invalid"):
        lane.render(room="lobby")
    for change in ({"room": "lobby"}, {"did": "did:key:other"}):
        with pytest.raises(lane.TeamRequestError):
            lane.save({**lane.new_state(), **change})


def test_cli_arguments_and_wrong_signer_user_fail_closed(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["sonnet_team_request", "lobby"])
    monkeypatch.setattr(lane, "run_once", lambda: pytest.fail("must not run"))
    with pytest.raises(SystemExit):
        lane.main()
    assert json.loads(capsys.readouterr().out) == {"ok": False, "error": "arguments_rejected"}
    with pytest.raises(lane.TeamRequestError, match="isolated_signer_user_required"):
        lane.require_signer_user("technocore")
    assert lane.require_signer_user("technocore-signer") is None
    if os.name != "posix":
        with pytest.raises(lane.TeamRequestError, match="isolated_linux_signer_required"):
            with lane.team_request_lock():
                pass


@pytest.mark.parametrize("condition", ["expected_did", "verified_did", "signer_pin"])
def test_identity_gate_rejects_before_sign_and_post(environment, monkeypatch, condition):
    if condition == "expected_did":
        monkeypatch.setenv("TECHNOCORE_SIGNER_EXPECTED_DID", "did:key:z6Mk" + "1" * 44)
    elif condition == "verified_did":
        (core.STATE / "verified-did.json").write_text(json.dumps({"did": "wrong"}), encoding="utf-8")
    else:
        monkeypatch.setattr(core, "signer_matches_pinned", lambda: False)
    with pytest.raises(RuntimeError):
        lane.run_once()
    assert environment["posts"] == environment["signs"] == []


@pytest.mark.parametrize("condition", ["missing", "not_posted", "wrong_role", "wrong_x"])
def test_writer_registration_gate_rejects(environment, monkeypatch, condition):
    original = registration.load()
    if condition == "missing":
        replacement = None
    elif condition == "not_posted":
        replacement = {**original, "state": "prepared"}
    elif condition == "wrong_role":
        replacement = {**original, "registration": {**original["registration"], "role": "reader"}}
    else:
        replacement = {**original, "registration": {**original["registration"], "x_account_url": "https://example.invalid"}}
    monkeypatch.setattr(registration, "load", lambda: replacement)
    with pytest.raises(lane.TeamRequestError, match="writer_registration"):
        lane.run_once()
    assert environment["posts"] == environment["signs"] == []


@pytest.mark.parametrize("condition", ["degraded", "stale", "events", "messages", "closed"])
def test_health_core_and_window_reject_before_sign(environment, monkeypatch, condition):
    snapshot = environment["snapshot"]
    if condition == "degraded": snapshot["health"] = "degraded"
    if condition == "stale": snapshot["updated_at"] = "2020-01-01T00:00:00+00:00"
    if condition == "events": snapshot["unrecoverable_core_gap_events"] += 1
    if condition == "messages": snapshot["unrecoverable_core_gap_messages"] += 1
    if condition == "closed": monkeypatch.setattr(lane, "CLOSE", datetime(2026, 9, 12, tzinfo=UTC))
    observer.atomic_json_write(core.STATE / "observer-safety.json", snapshot)
    with pytest.raises(lane.TeamRequestError):
        lane.run_once()
    assert environment["posts"] == environment["signs"] == []


def test_second_preflight_blocks_post_on_health_change(environment, monkeypatch):
    original = core.invoke_signer
    def sign(*args):
        result = original(*args)
        snapshot = environment["snapshot"]
        snapshot["health"] = "degraded"
        observer.atomic_json_write(core.STATE / "observer-safety.json", snapshot)
        return result
    monkeypatch.setattr(core, "invoke_signer", sign)
    with pytest.raises(lane.TeamRequestError, match="observer_safety_not_ok"):
        lane.run_once()
    assert environment["posts"] == []
    assert lane.load()["state"] == "prepared"


def test_existing_exact_signed_record_reconciles_without_post(environment):
    environment["rows"].append(environment["record"](lane.render(), "456"))
    result = lane.run_once()
    assert result["action"] == "reconciled"
    assert lane.load()["state"] == "posted" and lane.load()["nonce"] == "456"
    assert environment["posts"] == environment["signs"] == []


@pytest.mark.parametrize("change", [
    {"game_id": "other"}, {"contest_id": "sonnet-1", "request_id": "other"},
])
def test_conflicting_authenticated_request_id_or_game_binding_fails_closed(environment, change):
    text = json.dumps({**lane.PAYLOAD, **change}, sort_keys=True, separators=(",", ":"))
    environment["rows"].append(environment["record"](text))
    with pytest.raises(lane.TeamRequestError, match="existing_team_request_conflict"):
        lane.run_once()
    assert environment["posts"] == environment["signs"] == []


@pytest.mark.parametrize("state_name", ["attempting", "ambiguous"])
def test_uncertain_state_never_posts_again(environment, state_name):
    value = lane.new_state()
    value.update(state=state_name, nonce="123", git_commit_sha="a" * 40,
                 attempted_at="2026-09-14T00:00:00+00:00")
    lane.save(value)
    assert lane.run_once()["action"] == "ambiguous"
    assert environment["posts"] == environment["signs"] == []
    environment["rows"].append(environment["record"](lane.render()))
    assert lane.run_once()["action"] == "reconciled"
    assert environment["posts"] == environment["signs"] == []


def test_post_receipt_mismatch_is_ambiguous_and_never_reposts(environment, monkeypatch):
    def mismatch(url, *, json, timeout):
        environment["posts"].append(json)
        row = environment["record"](json["text"], str(int(json["nonce"]) + 1))
        return core.httpx.Response(200, json={"posted": row}, request=core.httpx.Request("POST", url))
    monkeypatch.setattr(core.httpx, "post", mismatch)
    with pytest.raises(lane.TeamRequestError, match="submission_unknown"):
        lane.run_once()
    saved = lane.load()
    assert saved["state"] == "ambiguous" and saved["nonce"]
    assert saved["attempted_at"] and saved["text_hash"] and saved["git_commit_sha"]
    assert lane.run_once()["action"] == "ambiguous"
    assert len(environment["posts"]) == 1


def test_failed_reconciliation_preserves_attempting_state(environment, monkeypatch):
    value = lane.new_state()
    value.update(state="attempting", nonce="123", git_commit_sha="a" * 40,
                 attempted_at="2026-09-14T00:00:00+00:00")
    lane.save(value)
    before = lane.state_path().read_bytes()
    monkeypatch.setattr(core, "read_room", lambda *_args, **_kwargs: (_ for _ in ()).throw(core.httpx.ConnectTimeout("mock")))
    with pytest.raises(core.httpx.HTTPError):
        lane.run_once()
    assert lane.state_path().read_bytes() == before
    assert environment["posts"] == environment["signs"] == []


def test_main_output_never_reflects_exception(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["sonnet_team_request"])
    monkeypatch.setattr(lane, "run_once", lambda: (_ for _ in ()).throw(RuntimeError("mock sensitive data")))
    with pytest.raises(SystemExit):
        lane.main()
    assert json.loads(capsys.readouterr().out) == {"ok": False, "error": "team_request_failed_closed"}


def test_one_shot_unit_has_isolated_signer_and_no_automatic_lifecycle():
    text = (core.ROOT / "packaging/oracle/technocore-safe-agent-sonnet-team-request.service").read_text("utf-8")
    for required in (
        "Type=oneshot", "User=technocore-signer", "Group=technocore-signer",
        "SupplementaryGroups=technocore-autopilot", "EnvironmentFile=/etc/technocore-safe-agent/signer.env",
        "FLOP_STATE_DIR=/var/lib/technocore-safe-agent", "PYTHONPATH=/opt/technocore-safe-agent/src",
        "UV_CACHE_DIR=/var/lib/technocore-safe-agent/signer/uv-cache",
        "NoNewPrivileges=true", "PrivateTmp=true", "PrivateDevices=true",
        "ProtectSystem=strict", "ProtectHome=true", "ProtectControlGroups=true",
        "ProtectKernelModules=true", "ProtectKernelTunables=true", "ProtectKernelLogs=true",
        "CapabilityBoundingSet=", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "ReadWritePaths=/var/lib/technocore-safe-agent/signer /var/lib/technocore-safe-agent/nonces.json",
        "-m flop_agent.sonnet_team_request",
    ):
        assert required in text
    for forbidden in ("[Install]", "Restart=", "SupplementaryGroups=technocore\n", "ExecStartPre=", ".timer"):
        assert forbidden not in text
