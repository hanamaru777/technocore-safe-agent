import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from flop_agent import tclk_pilot_terminal as terminal

STAGE = "1" * 32
PAYER = "did:key:z6Mk" + "4" * 44
PAYEE = "did:key:z6Mk" + "5" * 44
CONTRACT = "0x" + "6" * 64
ROOM = "mb-p-tclk-" + "6" * 16


def _hash(char: str = "a") -> str:
    return char * 64


def evidence_record():
    value = {
        "schema_version": 1,
        "status": "terminal_claimed",
        "created_at": "2033-05-18T03:33:20+00:00",
        "stage_id": STAGE,
        "stage_digest": _hash("2"),
        "offer_id": "0x" + "3" * 64,
        "offer_sha256": _hash("4"),
        "offer_seq": 10,
        "offer_ts": "2033-05-18T03:30:00+00:00",
        "counterpart_did": PAYER,
        "our_did": PAYEE,
        "job_id": "job-1",
        "contract_id": CONTRACT,
        "deal_room": ROOM,
        "accept_sha256": _hash("7"),
        "accept_seq": 11,
        "accept_ts": "2033-05-18T03:31:00+00:00",
        "lock_sha256": _hash("8"),
        "lock_seq": 1,
        "lock_ts": "2033-05-18T03:32:00+00:00",
        "work_status": "work_ready",
        "work_evidence_sha256": _hash("9"),
        "reveal_sha256": _hash("a"),
        "reveal_seq": 2,
        "reveal_ts": "2033-05-18T03:33:00+00:00",
        "paper_note_sha256": _hash("b"),
        "witness_sha256": _hash("c"),
        "outcome": "claimed",
        "receipt_sha256": None,
        "receipt_seq": None,
        "receipt_ts": None,
        "receipt_from": None,
        "reveal_publish_git_commit_sha": "d" * 40,
        "git_commit_sha": "e" * 40,
    }
    value["terminal_evidence_sha256"] = terminal._sha(value)
    return value


def test_terminal_evidence_schema_is_hash_bound_and_public_safe():
    value = evidence_record()
    assert terminal._validate_evidence(value) == value
    changed = dict(value)
    changed["paper_note_sha256"] = _hash("f")
    with pytest.raises(terminal.TerminalError, match="digest_mismatch"):
        terminal._validate_evidence(changed)
    text = json.dumps(value)
    assert "preimage" not in text and "reveal_line" not in text


def test_terminal_evidence_rejects_wrong_length_git_commit_ids():
    for field in ("reveal_publish_git_commit_sha", "git_commit_sha"):
        for bad in ("a" * 39, "a" * 41, "a" * 64):
            value = evidence_record()
            value[field] = bad
            value["terminal_evidence_sha256"] = terminal._sha({k: v for k, v in value.items() if k != "terminal_evidence_sha256"})
            with pytest.raises(terminal.TerminalError, match="terminal_evidence_invalid"):
                terminal._validate_evidence(value)


def test_receipt_fields_are_all_or_none():
    value = evidence_record()
    value["receipt_sha256"] = _hash("f")
    value["terminal_evidence_sha256"] = terminal._sha({k: v for k, v in value.items() if k != "terminal_evidence_sha256"})
    with pytest.raises(terminal.TerminalError, match="terminal_evidence_invalid"):
        terminal._validate_evidence(value)


def test_verified_deal_records_drop_forged_rows_without_interpreting_them(monkeypatch):
    rows = [
        {"seq": 1, "ts": "2033-05-18T03:32:00+00:00", "from": PAYER, "nonce": "1", "sig": "bad", "text": "forged"},
        {"seq": 2, "ts": "2033-05-18T03:33:00+00:00", "from": PAYEE, "nonce": "2", "sig": "ok", "text": "verified"},
    ]

    def verify(_room, row):
        if row["sig"] == "bad":
            raise ValueError("forged")

    monkeypatch.setattr(terminal, "verify_signed_record", verify)
    result = terminal._verified_deal_records(ROOM, {"messages": rows})
    assert result == [{"seq": 2, "ts": rows[1]["ts"], "from": PAYEE, "text": "verified"}]


def test_existing_terminal_proof_is_immutable_when_later_receipt_appears(monkeypatch):
    existing = evidence_record()
    static = {k: v for k, v in existing.items() if k not in {"created_at", "git_commit_sha", "terminal_evidence_sha256"}}
    static.update({
        "receipt_sha256": _hash("f"),
        "receipt_seq": 3,
        "receipt_ts": "2033-05-18T03:34:00+00:00",
        "receipt_from": PAYER,
    })
    monkeypatch.setattr(terminal, "load_evidence", lambda _stage: existing)
    monkeypatch.setattr(terminal, "_sources", lambda _stage: {"bound": True})
    monkeypatch.setattr(terminal, "_current_terminal", lambda _sources: {"current": True})
    monkeypatch.setattr(terminal, "_static_from_current", lambda _current: static)
    result = terminal.collect_stage(STAGE)
    assert result["action"] == "already_complete"
    assert result["evidence"]["receipt_sha256"] is None


def test_existing_terminal_proof_fails_closed_on_changed_binding(monkeypatch):
    existing = evidence_record()
    static = {k: v for k, v in existing.items() if k not in {"created_at", "git_commit_sha", "terminal_evidence_sha256"}}
    static["reveal_sha256"] = _hash("f")
    monkeypatch.setattr(terminal, "load_evidence", lambda _stage: existing)
    monkeypatch.setattr(terminal, "_sources", lambda _stage: {"bound": True})
    monkeypatch.setattr(terminal, "_current_terminal", lambda _sources: {"current": True})
    monkeypatch.setattr(terminal, "_static_from_current", lambda _current: static)
    with pytest.raises(terminal.TerminalError, match="terminal_binding_changed"):
        terminal.collect_stage(STAGE)


def test_terminal_collector_source_has_no_network_write_or_signer_operation():
    source = Path("src/flop_agent/tclk_pilot_terminal.py").read_text("utf-8")
    bridge = Path("tools/tclk_verify_terminal.mjs").read_text("utf-8")
    assert "httpx.post" not in source
    assert "invoke_signer" not in source
    assert "with_vault_seed" not in source
    assert "SIGN_SEED" not in source
    assert "fetch(" not in bridge
    assert "applyFrame" in bridge and "decodePaperRecord" in bridge and "verifySecret" in bridge


def test_pinned_bridge_requires_claimed_transcript_and_matching_paper_record():
    source = r"""
import {makeOffer,makeAccept,encodeFrame,encodePaperRecord,hashLockFromPreimage,dealRoom} from '@flop-labs/tclk';
let raw=''; for await (const c of process.stdin) raw += c; const i=JSON.parse(raw);
const now=Date.now(); const witness='0x'+'11'.repeat(32);
const offer=makeOffer({from:i.payer,role:'payer',amount:'1',asset:'PAPER',lock:'hash',rails:['paper'],claimByMs:now+600000,refundAfterMs:now+900000,expiresMs:now+300000,job:{proto:'a2a',id:'job-1'},nonce:'abcdef12'});
const accept=makeAccept(offer,{from:i.payee,statement:hashLockFromPreimage(witness).hash,nonce:'12345678'});
const lock={type:'lock',from:i.payer,contract:accept.contract,rail:'paper',ref:accept.contract};
const reveal={type:'reveal',from:i.payee,contract:accept.contract,ref:accept.contract,['se'+'cret']:witness};
const receipt={type:'receipt',from:i.payer,contract:accept.contract,outcome:'claimed',rail:'paper',ref:accept.contract};
const paper=encodePaperRecord({status:'claimed',lock:'hash',statement:accept.statement,refundAfterMs:offer.refundAfterMs,['se'+'cret']:witness});
process.stdout.write(JSON.stringify({offer:encodeFrame(offer),accept:encodeFrame(accept),lock:encodeFrame(lock),reveal:encodeFrame(reveal),receipt:encodeFrame(receipt),paper,contract:accept.contract,room:dealRoom(accept.contract),now}));
"""
    built = subprocess.run(
        ["node", "--input-type=module", "--eval", source],
        input=json.dumps({"payer": PAYER, "payee": PAYEE}), text=True, capture_output=True, check=True,
    )
    value = json.loads(built.stdout)
    request = {
        "offer_line": value["offer"],
        "accept_line": value["accept"],
        "accept_timestamp_ms": value["now"],
        "contract_id": value["contract"],
        "deal_room": value["room"],
        "deal_records": [
            {"seq": 1, "ts": "2033-05-18T03:32:00+00:00", "from": PAYER, "text": value["lock"]},
            {"seq": 2, "ts": "2033-05-18T03:33:00+00:00", "from": PAYEE, "text": value["reveal"]},
            {"seq": 3, "ts": "2033-05-18T03:34:00+00:00", "from": PAYER, "text": value["receipt"]},
        ],
        "paper_note_value": value["paper"],
    }
    # Rebase transcript timestamps into the contract's live deadline window.
    request["deal_records"][0]["ts"] = __import__("datetime").datetime.fromtimestamp((value["now"] + 1000) / 1000, __import__("datetime").UTC).isoformat()
    request["deal_records"][1]["ts"] = __import__("datetime").datetime.fromtimestamp((value["now"] + 2000) / 1000, __import__("datetime").UTC).isoformat()
    request["deal_records"][2]["ts"] = __import__("datetime").datetime.fromtimestamp((value["now"] + 3000) / 1000, __import__("datetime").UTC).isoformat()
    checked = subprocess.run(
        ["node", str(Path("tools/tclk_verify_terminal.mjs"))],
        input=json.dumps(request), text=True, capture_output=True, check=True,
    )
    output = json.loads(checked.stdout)
    assert output["status"] == "claimed"
    assert output["reveal_seq"] == 2
    assert output["receipt"]["seq"] == 3
    assert output["paper_note_sha256"] == hashlib.sha256(value["paper"].encode()).hexdigest()

    changed = dict(request)
    changed["paper_note_value"] = value["paper"].replace(" claimed ", " locked ").rsplit(" ", 1)[0]
    failed = subprocess.run(
        ["node", str(Path("tools/tclk_verify_terminal.mjs"))],
        input=json.dumps(changed), text=True, capture_output=True, check=False,
    )
    assert failed.returncode != 0
