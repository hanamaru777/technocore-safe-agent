import base64
import json
import os
import sys
from contextlib import nullcontext
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from flop_agent import core, oracle_signer, public_record
from flop_agent import sonnet_mitsuri_contact as lane
from flop_agent import sonnet_mitsuri_contact_v2 as bootstrap


@pytest.fixture
def environment(monkeypatch, tmp_path):
    key = Ed25519PrivateKey.generate()
    number = int.from_bytes(b"\xed\x01" + key.public_key().public_bytes_raw(), "big")
    encoded = ""
    while number:
        number, rem = divmod(number, 58)
        encoded = public_record.B58[rem] + encoded
    did = "did:key:z" + encoded

    original_did = lane.DID
    original_payload_did = lane.PAYLOAD["did"]
    monkeypatch.setattr(lane, "DID", did)
    lane.PAYLOAD["did"] = did
    monkeypatch.setattr(core, "STATE", tmp_path)
    (tmp_path / "signer").mkdir()
    monkeypatch.setattr(lane, "contact_lock", nullcontext)
    monkeypatch.setattr(lane, "require_identity", lambda: None)
    monkeypatch.setattr(lane, "require_health", lambda: None)
    monkeypatch.setattr(lane, "require_registration_posted", lambda: None)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 9, 15, 8, tzinfo=UTC)

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
        assert lane.load()["state"] == "attempting"
        posts.append(json)
        row = record(json["text"], json["nonce"])
        rows.append(row)
        return core.httpx.Response(
            200,
            json={"posted": row},
            request=core.httpx.Request("POST", url),
        )

    monkeypatch.setattr(core.httpx, "post", post)
    yield rows, posts, signs, buffers, record, did
    lane.PAYLOAD["did"] = original_payload_did
    monkeypatch.setattr(lane, "DID", original_did)


def test_fixed_payload_is_nonbinding_and_targeted():
    assert lane.ROOM == "mb-sonnet-2-discovery"
    assert lane.REQUEST_ID == "maru-mitsuri-contact-20260915-1"
    assert lane.TARGET_DID == "did:key:z6MkrjMTaN3kDvff5kdE6BhNxgErLdpz58kmsipP3PuHwoct"
    assert lane.PAYLOAD["type"] == "sonnet.application.v1"
    assert lane.PAYLOAD["target_did"] == lane.TARGET_DID
    assert lane.PAYLOAD["no_live_roster_consent"] is True
    assert "not claiming accepted writer status" in lane.PAYLOAD["text"]
    assert "not roster consent or a word proposal" in lane.PAYLOAD["text"]
    assert "registration_receipt_seq" not in lane.PAYLOAD
    assert "game_id" not in lane.PAYLOAD


def test_binding_rejects_mutation():
    changed = dict(lane.PAYLOAD)
    changed["target_did"] = "did:key:zOther"
    with pytest.raises(lane.ContactError, match="contact_binding_invalid"):
        lane.render(changed)


def test_posts_exactly_once(environment):
    _, posts, signs, buffers, _, _ = environment
    result = lane.run_once()
    assert result["status"] == "posted"
    assert len(posts) == len(signs) == 1
    assert json.loads(posts[0]["text"]) == lane.PAYLOAD
    assert all(not any(buf) for buf in buffers)
    assert "SIGN_SEED" not in os.environ

    second = lane.run_once()
    assert second["status"] in {"reconciled", "already_posted"}
    assert len(posts) == len(signs) == 1


def test_health_failure_blocks_before_sign_or_post(environment, monkeypatch):
    _, posts, signs, _, _, _ = environment
    monkeypatch.setattr(
        lane,
        "require_health",
        lambda: (_ for _ in ()).throw(lane.ContactError("observer_health_not_ok")),
    )
    with pytest.raises(lane.ContactError, match="observer_health_not_ok"):
        lane.run_once()
    assert posts == signs == []


def test_ambiguity_is_terminal(environment, monkeypatch):
    _, posts, signs, _, _, _ = environment

    def fail(*args, **kwargs):
        posts.append(kwargs["json"])
        raise core.httpx.ConnectTimeout("dummy")

    monkeypatch.setattr(core.httpx, "post", fail)
    with pytest.raises(lane.ContactError, match="submission_unknown"):
        lane.run_once()
    assert lane.load()["state"] == "ambiguous"
    before = (len(posts), len(signs))
    result = lane.run_once()
    assert result["status"] == "ambiguous"
    assert (len(posts), len(signs)) == before


def test_conflicting_existing_request_fails_closed(environment):
    rows, posts, signs, _, record, _ = environment
    changed = dict(lane.PAYLOAD)
    changed["text"] = "changed"
    text = json.dumps(changed, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    rows.append(record(text, "123"))
    with pytest.raises(lane.ContactError, match="existing_contact_conflict"):
        lane.run_once()
    assert posts == signs == []


def test_bootstrap_detects_exact_existing_without_signing(environment, monkeypatch):
    rows, posts, signs, _, record, _ = environment
    rows.append(record(lane.render(), "123"))
    monkeypatch.setattr(bootstrap, "read_export_rows", lambda: list(rows))
    monkeypatch.setattr(
        lane,
        "run_once",
        lambda: pytest.fail("must not sign/post when export already contains request"),
    )
    result = bootstrap.run_once()
    assert result["status"] == "existing_contact_detected"
    assert result["request_id"] == lane.REQUEST_ID
    assert posts == signs == []


def test_bootstrap_conflicting_request_fails_closed(environment, monkeypatch):
    rows, _, _, _, record, _ = environment
    changed = dict(lane.PAYLOAD)
    changed["text"] = "conflict"
    text = json.dumps(changed, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    rows.append(record(text, "123"))
    monkeypatch.setattr(bootstrap, "read_export_rows", lambda: list(rows))
    with pytest.raises(bootstrap.BootstrapError, match="existing_contact_conflict"):
        bootstrap.run_once()


def test_cli_args_rejected(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["sonnet_mitsuri_contact", "extra"])
    monkeypatch.setattr(lane, "run_once", lambda: pytest.fail("must not execute"))
    with pytest.raises(SystemExit):
        lane.main()
