import base64
import json
import os
import sys
from contextlib import nullcontext
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from flop_agent import core, observer, oracle_signer, public_record, sonnet_registration as lane


@pytest.fixture
def environment(monkeypatch, tmp_path):
    # Fresh dummy key only; real Vault, Technocore and signer processes never run.
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
    monkeypatch.setattr(lane, "registration_lock", nullcontext)
    monkeypatch.setenv("TECHNOCORE_SIGNER_EXPECTED_DID", did)
    (tmp_path / "verified-did.json").write_text(json.dumps({"did": did}), encoding="utf-8")
    monkeypatch.setattr(core, "git_commit_sha", lambda: "a" * 40)
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 9, 12, tzinfo=UTC)
    monkeypatch.setattr(lane, "datetime", Clock)
    observed = {"updated_at": Clock.now().isoformat(), "health": {"current": "ok"},
                "metrics": {"unrecoverable_core_gap_events": 117, "unrecoverable_core_gap_messages": 5083155}}
    monkeypatch.setattr(observer, "load_state", lambda: observed)
    rows, posts, signs, buffers = [], [], [], []
    def read(room, **kwargs):
        assert room == lane.ROOM and kwargs["limit"] == 200 and kwargs["cache_buster"]
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
    def record(text, nonce="123"):
        return {"from": did, "nonce": nonce, "text": text, "seq": 1, "ts": Clock.now().isoformat(),
                "sig": base64.urlsafe_b64encode(key.sign(f"{lane.ROOM}|{nonce}|{text}".encode())).decode().rstrip("=")}
    def post(url, *, json, timeout):
        assert url == f"{core.BASE_URL}/r/{lane.ROOM}?format=json"
        assert lane.load()["state"] == "attempting"
        assert "SIGN_SEED" not in os.environ
        posts.append(json)
        row = record(json["text"], json["nonce"])
        rows.append(row)
        return core.httpx.Response(200, json={"posted": row}, request=core.httpx.Request("POST", url))
    monkeypatch.setattr(core.httpx, "post", post)
    return observed, rows, posts, signs, buffers, record


def test_exact_canonical_writer_registration_and_secret_lifecycle(environment):
    _, _, posts, signs, buffers, _ = environment
    assert lane.run_once()["action"] == "posted"
    value = lane.load()
    assert json.loads(posts[0]["text"]) == {**lane.FIXED, "request_id": value["registration"]["request_id"]}
    assert posts[0]["text"] == lane.render(value["registration"])
    assert len(signs) == len(posts) == 1
    assert all(not any(buf) for buf in buffers) and "SIGN_SEED" not in os.environ
    assert lane.run_once()["action"] == "already_posted"
    assert len(posts) == 1
    assert set(value) == {"schema_version", "room", "did", "registration", "state", "nonce", "text_hash", "git_commit_sha", "attempted_at", "seq", "ts", "posted_record"}


@pytest.mark.parametrize("field,value", [("contest_id", "sonnet-1"), ("role", "reader"), ("x_account_url", "https://example.invalid"), ("type", "anything"), ("text", "arbitrary"), ("request_id", "x;echo")])
def test_wrong_bindings_and_arbitrary_fields_rejected(field, value):
    with pytest.raises(lane.RegistrationError):
        lane.render({**lane.FIXED, "request_id": "a" * 32, field: value})


def test_wrong_room_and_cli_arguments_rejected(monkeypatch):
    with pytest.raises(lane.RegistrationError):
        lane.render({**lane.FIXED, "request_id": "a" * 32}, "lobby")
    monkeypatch.setattr(sys, "argv", ["sonnet_registration", "arbitrary"])
    monkeypatch.setattr(lane, "run_once", lambda: pytest.fail("must not execute"))
    with pytest.raises(SystemExit):
        lane.main()


@pytest.mark.parametrize("condition", ["degraded", "events", "messages", "missing", "stale"])
def test_health_fail_closed_before_vault_or_post(environment, monkeypatch, condition):
    observed, _, posts, signs, _, _ = environment
    if condition == "degraded": observed["health"]["current"] = "degraded"
    if condition == "events": observed["metrics"]["unrecoverable_core_gap_events"] += 1
    if condition == "messages": observed["metrics"]["unrecoverable_core_gap_messages"] += 1
    if condition == "stale": observed["updated_at"] = "2020-01-01T00:00:00+00:00"
    if condition == "missing": monkeypatch.setattr(observer, "load_state", lambda: (_ for _ in ()).throw(PermissionError()))
    with pytest.raises(lane.RegistrationError): lane.run_once()
    assert posts == signs == []


def test_health_change_during_signing_blocks_post(environment, monkeypatch):
    observed, _, posts, _, _, _ = environment
    original = core.invoke_signer
    def sign(*args):
        result = original(*args)
        observed["health"]["current"] = "degraded"
        return result
    monkeypatch.setattr(core, "invoke_signer", sign)
    with pytest.raises(lane.RegistrationError): lane.run_once()
    assert posts == [] and lane.load()["state"] == "prepared"


@pytest.mark.parametrize("failure", ["503", "timeout", "mismatch", "crash"])
def test_ambiguous_attempt_reuses_request_and_never_reposts(environment, monkeypatch, failure):
    _, rows, posts, signs, _, record = environment
    def fail(*args, **kwargs):
        posts.append(kwargs["json"])
        if failure == "crash": raise KeyboardInterrupt()
        if failure == "timeout": raise core.httpx.ConnectTimeout("dummy transport error")
        status = 503 if failure == "503" else 200
        return core.httpx.Response(status, json={"posted": {}}, request=core.httpx.Request("POST", args[0]))
    monkeypatch.setattr(core.httpx, "post", fail)
    with pytest.raises((lane.RegistrationError, KeyboardInterrupt)): lane.run_once()
    saved = lane.load()
    assert saved["state"] in {"ambiguous", "attempting"}
    assert lane.run_once()["action"] == "ambiguous"
    assert lane.load()["registration"] == saved["registration"] and len(posts) == len(signs) == 1
    rows.append(record(lane.render(saved["registration"]), saved["nonce"]))
    assert lane.run_once()["action"] == "reconciled"
    assert lane.run_once()["action"] == "already_posted"
    assert len(posts) == len(signs) == 1


def test_existing_signed_registration_suppresses_duplicate(environment):
    _, rows, posts, signs, _, record = environment
    rows.append(record(lane.render({**lane.FIXED, "request_id": "c" * 32})))
    assert lane.run_once()["action"] == "reconciled"
    assert posts == signs == []


def test_wrong_expected_did_or_unpinned_signer_blocks(environment, monkeypatch):
    monkeypatch.setenv("TECHNOCORE_SIGNER_EXPECTED_DID", "did:key:z6Mk" + "1" * 44)
    with pytest.raises(lane.RegistrationError, match="did_mismatch"): lane.run_once()
    monkeypatch.setenv("TECHNOCORE_SIGNER_EXPECTED_DID", lane.DID)
    monkeypatch.setattr(core, "signer_matches_pinned", lambda: False)
    with pytest.raises(lane.RegistrationError, match="signer_not_pinned"): lane.run_once()
    assert environment[2] == environment[3] == []


def test_error_output_never_contains_exception_content(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["sonnet_registration"])
    monkeypatch.setattr(lane, "run_once", lambda: (_ for _ in ()).throw(RuntimeError("dummy sensitive exception material")))
    with pytest.raises(SystemExit): lane.main()
    assert json.loads(capsys.readouterr().out) == {"ok": False, "error": "registration_failed_closed"}


def test_one_shot_unit_preserves_isolation_and_cannot_auto_start():
    text = (core.ROOT / "packaging/oracle/technocore-safe-agent-sonnet-registration.service").read_text("utf-8")
    for required in ("Type=oneshot", "User=technocore-signer", "Group=technocore-signer", "SupplementaryGroups=technocore-autopilot", "NoNewPrivileges=true", "ProtectSystem=strict", "-m flop_agent.sonnet_registration"):
        assert required in text
    for forbidden in ("[Install]", "Restart=", "SupplementaryGroups=technocore\n", "/etc/technocore-safe-agent/env", "autopilot /"):
        assert forbidden not in text


def test_read_failure_after_ambiguity_retains_evidence(environment, monkeypatch):
    def fail(*args, **kwargs): raise core.httpx.ConnectTimeout("dummy")
    monkeypatch.setattr(core.httpx, "post", fail)
    with pytest.raises(lane.RegistrationError): lane.run_once()
    before = lane.state_path().read_bytes()
    monkeypatch.setattr(core, "read_room", fail)
    with pytest.raises(core.httpx.HTTPError): lane.run_once()
    assert lane.state_path().read_bytes() == before
    assert len(environment[3]) == 1


def test_signed_child_failure_clears_seed_and_reuses_request(environment, monkeypatch):
    original = core.invoke_signer
    def failure(*args): raise RuntimeError("dummy child failure")
    monkeypatch.setattr(core, "invoke_signer", failure)
    with pytest.raises(RuntimeError): lane.run_once()
    before = lane.load()
    assert before["state"] == "prepared" and "SIGN_SEED" not in os.environ
    assert all(not any(value) for value in environment[4])
    monkeypatch.setattr(core, "invoke_signer", original)
    assert lane.run_once()["action"] == "posted"
    assert lane.load()["registration"] == before["registration"]
    assert lane.load()["nonce"] == before["nonce"]
