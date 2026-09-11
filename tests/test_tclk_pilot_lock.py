import json
import secrets
import subprocess
from datetime import UTC, datetime

import pytest

from flop_agent import core, tclk_pilot_lock, tclk_pilot_signer


STAGE_ID = "1" * 32
STAGE_DIGEST = "2" * 64
OFFER_ID = "0x" + "3" * 64
CONTRACT_ID = "0x" + "4" * 64
DEAL_ROOM = "mb-p-tclk-" + "5" * 16
PAYER = "did:key:z6Mk" + "6" * 44
PAYEE = "did:key:z6Mk" + "7" * 44
ACCEPT_LINE = "tclk1 {\"type\":\"accept\"}"
ACCEPT_HASH = __import__("hashlib").sha256(ACCEPT_LINE.encode()).hexdigest()


def stage():
    return {
        "stage_id": STAGE_ID,
        "stage_digest": STAGE_DIGEST,
        "offer_id": OFFER_ID,
        "counterpart_did": PAYER,
        "our_did": PAYEE,
        "job_id": "job-1",
        "rail": "paper",
        "lock": "hash",
    }


def preview():
    return {
        "accept_line": ACCEPT_LINE,
        "accept_sha256": ACCEPT_HASH,
        "contract_id": CONTRACT_ID,
        "deal_room": DEAL_ROOM,
    }


def activity():
    return {
        "action": "tclk_first_pilot_accept",
        "room": "tclk-offers",
        "did": PAYEE,
        "text": ACCEPT_LINE,
        "seq": 12,
        "ts": "2033-05-18T03:33:20Z",
        "nonce": "2000000000000",
        "hash": "a" * 64,
    }


def verified_bridge_result():
    return {
        "ok": True,
        "status": "locked",
        "contract_id": CONTRACT_ID,
        "deal_room": DEAL_ROOM,
        "offer_id": OFFER_ID,
        "offer_from": PAYER,
        "offer_role": "payer",
        "accept_from": PAYEE,
        "accept_nonce": activity()["nonce"],
        "accept_seq": activity()["seq"],
        "accept_timestamp_ms": 2_000_000_000_000,
        "accept_line_sha256": ACCEPT_HASH,
        "lock_present": True,
        "lock_verified": True,
        "lock_from": PAYER,
        "lock_rail": "paper",
        "lock_ref": CONTRACT_ID,
        "lock_seq": 3,
        "lock_timestamp_ms": 2_000_000_001_000,
        "lock_line_sha256": "b" * 64,
        "paper_note_namespace": f"tclk-paper-{CONTRACT_ID[2:4]}",
        "paper_note_key": CONTRACT_ID[4:18],
        "paper_note_status": "locked",
        "paper_note_sha256": "c" * 64,
    }


def setup_public_bindings(monkeypatch):
    monkeypatch.setattr(tclk_pilot_lock.tclk_pilot, "load_stage", lambda *_a, **_k: stage())
    monkeypatch.setattr(tclk_pilot_signer, "_load_preview", lambda *_a, **_k: preview())
    monkeypatch.setattr(tclk_pilot_signer, "_require_preview_binding", lambda *_a, **_k: None)


def test_waiting_accept_never_reads_network(monkeypatch):
    setup_public_bindings(monkeypatch)
    monkeypatch.setattr(tclk_pilot_lock, "_load_activities", lambda: [])

    def no_network(*_a, **_k):
        raise AssertionError("network must stay idle before a posted accept activity exists")

    result = tclk_pilot_lock.inspect_stage(STAGE_ID, room_reader=no_network, note_reader=no_network)
    assert result == {"action": "waiting_accept", "stage_id": STAGE_ID}


def test_verified_lock_persists_public_hash_only_evidence(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    setup_public_bindings(monkeypatch)
    monkeypatch.setattr(tclk_pilot_lock, "_load_activities", lambda: [activity()])
    monkeypatch.setattr(tclk_pilot_lock, "_run_bridge", lambda _request: verified_bridge_result())

    room_reader = lambda *_a, **_k: {"messages": []}
    note_reader = lambda *_a, **_k: "tclkpaper1 locked hash 0x" + "d" * 64 + " 2000000100000"
    result = tclk_pilot_lock.inspect_stage(STAGE_ID, room_reader=room_reader, note_reader=note_reader)

    assert result["action"] == "lock_verified"
    evidence = result["evidence"]
    assert evidence["contract_id"] == CONTRACT_ID
    assert evidence["lock_from"] == PAYER
    assert evidence["lock_ref"] == CONTRACT_ID
    assert tclk_pilot_lock.evidence_path(STAGE_ID).is_file()
    assert not any(key in evidence for key in ("secret", "preimage", "seed", "private_key", "lock_line", "paper_note_value"))


def test_unverified_paper_lock_never_persists(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    setup_public_bindings(monkeypatch)
    monkeypatch.setattr(tclk_pilot_lock, "_load_activities", lambda: [activity()])
    result_data = verified_bridge_result()
    result_data["lock_verified"] = False
    monkeypatch.setattr(tclk_pilot_lock, "_run_bridge", lambda _request: result_data)

    result = tclk_pilot_lock.inspect_stage(
        STAGE_ID,
        room_reader=lambda *_a, **_k: {"messages": []},
        note_reader=lambda *_a, **_k: None,
    )
    assert result["action"] == "waiting_verified_paper_lock"
    assert not tclk_pilot_lock.evidence_path(STAGE_ID).exists()


def test_accept_transport_binding_mismatch_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    setup_public_bindings(monkeypatch)
    monkeypatch.setattr(tclk_pilot_lock, "_load_activities", lambda: [activity()])
    result_data = verified_bridge_result()
    result_data["accept_seq"] += 1
    monkeypatch.setattr(tclk_pilot_lock, "_run_bridge", lambda _request: result_data)

    with pytest.raises(tclk_pilot_lock.LockError, match="transcript_binding_mismatch"):
        tclk_pilot_lock.inspect_stage(
            STAGE_ID,
            room_reader=lambda *_a, **_k: {"messages": []},
            note_reader=lambda *_a, **_k: "paper",
        )


def _did(monkeypatch, seed):
    monkeypatch.setenv("SIGN_SEED", seed)
    return core.current_did()


def _signed_record(monkeypatch, seed, did, room, nonce, text, seq, ts):
    monkeypatch.setenv("SIGN_SEED", seed)
    signed_did, signature = core.invoke_signer("say", room, nonce, text)
    assert signed_did == did
    return {"seq": seq, "from": did, "nonce": nonce, "sig": signature, "text": text, "ts": ts}


def test_pinned_bridge_accepts_only_authenticated_payer_paper_lock(monkeypatch):
    payer_seed = secrets.token_hex(32)
    payee_seed = secrets.token_hex(32)
    payer = _did(monkeypatch, payer_seed)
    payee = _did(monkeypatch, payee_seed)

    source = r"""
import { makeOffer, generateHashLock, makeAccept, encodeFrame, dealRoom } from '@flop-labs/tclk';
let raw = ''; for await (const chunk of process.stdin) raw += chunk;
const input = JSON.parse(raw);
const now = Date.now();
const offer = makeOffer({
  from: input.payer,
  role: 'payer',
  amount: '1',
  asset: 'PAPER',
  lock: 'hash',
  rails: ['paper'],
  claimByMs: now + 300000,
  refundAfterMs: now + 600000,
  expiresMs: now + 240000,
  job: {proto: 'a2a', id: 'job-bridge-1'},
  nonce: 'abcdef12',
});
const minted = generateHashLock();
const accept = makeAccept(offer, {from: input.payee, statement: minted.hash});
const lock = {type: 'lock', from: input.payer, contract: accept.contract, rail: 'paper', ref: accept.contract};
process.stdout.write(JSON.stringify({
  offer: encodeFrame(offer),
  accept: encodeFrame(accept),
  lock: encodeFrame(lock),
  contract: accept.contract,
  room: dealRoom(accept.contract),
  paper: `tclkpaper1 locked hash ${minted.hash} ${offer.refundAfterMs}`,
}));
"""
    built = subprocess.run(
        ["node", "--input-type=module", "--eval", source],
        input=json.dumps({"payer": payer, "payee": payee}),
        text=True,
        capture_output=True,
        check=True,
    )
    frames = json.loads(built.stdout)
    ts0 = datetime.now(UTC).isoformat()
    offer_record = _signed_record(monkeypatch, payer_seed, payer, "tclk-offers", "1", frames["offer"], 1, ts0)
    accept_record = _signed_record(monkeypatch, payee_seed, payee, "tclk-offers", "2", frames["accept"], 2, ts0)
    lock_record = _signed_record(monkeypatch, payer_seed, payer, frames["room"], "3", frames["lock"], 1, ts0)

    result = tclk_pilot_lock._run_bridge({
        "contract_id": frames["contract"],
        "deal_room": frames["room"],
        "offer_records": [offer_record, accept_record],
        "deal_records": [lock_record],
        "paper_note_value": frames["paper"],
    })
    assert result["lock_verified"] is True
    assert result["offer_role"] == "payer"
    assert result["offer_from"] == payer
    assert result["accept_from"] == payee
    assert result["lock_from"] == payer
    assert result["lock_ref"] == frames["contract"]

    forged = dict(lock_record)
    forged["sig"] = "A" * 86
    forged_result = tclk_pilot_lock._run_bridge({
        "contract_id": frames["contract"],
        "deal_room": frames["room"],
        "offer_records": [offer_record, accept_record],
        "deal_records": [forged],
        "paper_note_value": frames["paper"],
    })
    assert forged_result["lock_verified"] is False


def test_lock_watcher_service_is_read_only_hardened():
    service = (core.ROOT / "packaging" / "oracle" / "technocore-safe-agent-tclk-lock-watcher.service").read_text("utf-8")
    timer = (core.ROOT / "packaging" / "oracle" / "technocore-safe-agent-tclk-lock-watcher.timer").read_text("utf-8")
    assert "Type=oneshot" in service
    assert "User=technocore" in service
    assert "SupplementaryGroups=technocore-autopilot" in service
    assert "-m flop_agent.tclk_pilot_lock" in service
    assert "IPAddressDeny=169.254.169.254" in service
    assert "EnvironmentFile=/etc/technocore-safe-agent/signer.env" not in service
    assert "ReadWritePaths=/var/lib/technocore-safe-agent/autopilot" in service
    assert "OnUnitActiveSec=30" in timer
