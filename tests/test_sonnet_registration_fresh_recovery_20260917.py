import importlib.util
from pathlib import Path

import pytest

PATH = Path("src/flop_agent/sonnet_registration_fresh_recovery_20260917.py")
spec = importlib.util.spec_from_file_location(
    "flop_agent.sonnet_registration_fresh_recovery_20260917", PATH
)
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)


def test_fresh_payload_preserves_identity_role_and_x_binding():
    assert mod.OLD_REQUEST_ID == "32c15433c6d73af1cea5d6467dece016"
    assert mod.REQUEST_ID == "maru-sonnet2-writer-fresh-20260917-1"
    assert mod.PAYLOAD == {
        "type": "sonnet.register.v1",
        "contest_id": "sonnet-2",
        "role": "writer",
        "x_account_url": "https://x.com/MinerMaru73",
        "request_id": mod.REQUEST_ID,
    }
    assert mod.OLD_PAYLOAD == {**mod.PAYLOAD, "request_id": mod.OLD_REQUEST_ID}


def test_receipt_matching_is_exact_on_request_and_did():
    target = {
        "type": "sonnet.receipt.v1",
        "request_id": mod.REQUEST_ID,
        "sender_did": mod.DID,
        "status": "accepted",
        "intake_seq": 123,
    }
    assert mod._receipt_item(target, mod.REQUEST_ID) == target
    assert mod._receipt_item(target, mod.OLD_REQUEST_ID) is None
    wrong_did = dict(target, sender_did="did:key:z6MkWrong")
    assert mod._receipt_item(wrong_did, mod.REQUEST_ID) is None


def test_old_authority_blocks_fresh_write(monkeypatch):
    monkeypatch.setattr(
        mod,
        "_find_receipt",
        lambda rows, request_id: {"status": "accepted"} if request_id == mod.OLD_REQUEST_ID else None,
    )
    monkeypatch.setattr(mod, "_fresh_post_visible", lambda rows: False)
    with pytest.raises(mod.FreshRegistrationError, match="old_request_authority_visible"):
        mod._prewrite_authority_check([])


def test_fresh_request_already_visible_blocks_duplicate(monkeypatch):
    monkeypatch.setattr(mod, "_find_receipt", lambda rows, request_id: None)
    monkeypatch.setattr(mod, "_fresh_post_visible", lambda rows: True)
    with pytest.raises(mod.FreshRegistrationError, match="fresh_request_authority_already_visible"):
        mod._prewrite_authority_check([])


def test_state_is_separate_and_source_is_exactly_once():
    assert mod.state_path().name == "sonnet-2-registration-fresh-recovery-20260917.json"
    source = PATH.read_text("utf-8")
    assert source.count("core.httpx.post(") == 1
    assert "registration.require_health()" in source
    assert source.count("_prewrite_authority_check(rows)") == 2
    assert "secrets.token_hex(16)" not in source
    assert "maru-sonnet2-writer-fresh-20260917-1" in source
