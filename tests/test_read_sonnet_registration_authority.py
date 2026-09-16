import importlib.util
from pathlib import Path


PATH = Path("packaging/oracle/read-sonnet-registration-authority.py")
spec = importlib.util.spec_from_file_location("maru_registration_readback", PATH)
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)


def test_individual_receipt_matches_exact_request_and_did():
    payload = {
        "type": "sonnet.receipt.v1",
        "contest_id": "sonnet-2",
        "request_id": mod.REQUEST_ID,
        "sender_did": mod.DID,
        "status": "accepted",
        "intake_seq": 123,
    }
    assert mod.receipt_from_payload(payload) == payload
    payload["sender_did"] = "did:key:z6MkWrong"
    assert mod.receipt_from_payload(payload) is None


def test_batch_receipt_matches_exact_request_and_did():
    target = {
        "request_id": mod.REQUEST_ID,
        "participant_did": mod.DID,
        "status": "accepted",
        "intake_seq": 456,
    }
    payload = {
        "type": "sonnet.receipts.v1",
        "contest_id": "sonnet-2",
        "receipts": [
            {"request_id": "other", "sender_did": mod.DID, "status": "accepted"},
            target,
        ],
    }
    assert mod.receipt_from_payload(payload) == target


def test_attestation_did_search_is_exact_string_match():
    payload = {
        "type": "sonnet.identities.v1",
        "identities": [{"did": mod.DID, "status": "verified"}],
    }
    assert mod.contains_did(payload)
    assert not mod.contains_did({"did": mod.DID + "suffix"})


def test_script_is_read_only_by_construction():
    source = PATH.read_text("utf-8")
    forbidden = ["httpx.post", "invoke_signer", "with_vault_seed", "make_nonce", "atomic_json_write"]
    for token in forbidden:
        assert token not in source
    assert "/export" in source
    assert mod.REFEREE_DID == "did:key:z6MkowHQwsx9xr84WbWN3YCnKutyBnBXkT1ChKY4uEAAMzte"
