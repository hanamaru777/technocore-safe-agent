import hashlib
import json
import os
import subprocess

import pytest

from flop_agent import core, tclk_pilot_reveal


STAGE_ID = "d" * 32
STAGE_DIGEST = "e" * 64
PAYER = "did:key:z6Mk" + "4" * 44
PAYEE = "did:key:z6Mk" + "5" * 44
LOCK_HASH = "7" * 64
PAPER_HASH = "8" * 64
WORK_HASH = "9" * 64


def _build_handshake():
    source = r"""
import { makeOffer, makeAccept, encodeFrame, dealRoom, hashLockFromPreimage } from '@flop-labs/tclk';
let raw = ''; for await (const chunk of process.stdin) raw += chunk;
const input = JSON.parse(raw);
const preimage = '0x' + '33'.repeat(32);
const now = Date.now();
const offer = makeOffer({
  from: input.payer, role: 'payer', amount: '1', asset: 'PAPER', lock: 'hash', rails: ['paper'],
  claimByMs: now + 600000, refundAfterMs: now + 900000, expiresMs: now + 300000,
  job: {proto: 'a2a', id: 'job-ref-1'}, nonce: 'abcdef12',
});
const accept = makeAccept(offer, {from: input.payee, statement: hashLockFromPreimage(preimage).hash, nonce: '12345678'});
process.stdout.write(JSON.stringify({offer: encodeFrame(offer), offerId: offer.id, accept: encodeFrame(accept), contract: accept.contract, room: dealRoom(accept.contract), preimage, expires: offer.expiresMs}));
"""
    result = subprocess.run(
        ["node", "--input-type=module", "--eval", source],
        input=json.dumps({"payer": PAYER, "payee": PAYEE}),
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(result.stdout)


def _decode_reveal(line: str) -> dict:
    source = r"""
import { decodeFrame } from '@flop-labs/tclk';
let raw = ''; for await (const chunk of process.stdin) raw += chunk;
const input = JSON.parse(raw);
const frame = decodeFrame(input.line);
process.stdout.write(JSON.stringify({type: frame.type, from: frame.from, contract: frame.contract, ref: frame.ref}));
"""
    result = subprocess.run(
        ["node", "--input-type=module", "--eval", source],
        input=json.dumps({"line": line}),
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(result.stdout)


def test_private_reveal_binds_exact_preceding_lock_ref(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    values = _build_handshake()
    accept_hash = hashlib.sha256(values["accept"].encode()).hexdigest()

    private = core.STATE / "signer" / "tclk-pilot-secrets" / f"{STAGE_ID}.json"
    private.parent.mkdir(parents=True, mode=0o700)
    private.write_text(json.dumps({
        "schema_version": 1,
        "stage_id": STAGE_ID,
        "offer_id": values["offerId"],
        "contract_id": values["contract"],
        "accept_nonce": "12345678",
        "preimage": values["preimage"],
    }))
    os.chmod(private, 0o600)

    request = {
        "stage_id": STAGE_ID,
        "stage_digest": STAGE_DIGEST,
        "offer_id": values["offerId"],
        "offer_line": values["offer"],
        "counterpart_did": PAYER,
        "our_did": PAYEE,
        "job_id": "job-ref-1",
        "accept_line": values["accept"],
        "accept_sha256": accept_hash,
        "contract_id": values["contract"],
        "deal_room": values["room"],
        "lock_line_sha256": LOCK_HASH,
        "lock_ref": values["contract"],
        "paper_note_sha256": PAPER_HASH,
        "work_evidence_sha256": WORK_HASH,
        "expires_ms": values["expires"],
    }
    output = tclk_pilot_reveal._run_bridge(request)
    stored = json.loads(tclk_pilot_reveal.private_reveal_path(STAGE_ID).read_text())
    decoded = _decode_reveal(stored["reveal_line"])

    assert decoded == {
        "type": "reveal",
        "from": PAYEE,
        "contract": values["contract"],
        "ref": values["contract"],
    }
    assert stored["lock_ref"] == values["contract"]
    assert output["lock_ref"] == values["contract"]

    wrong = dict(request)
    wrong["lock_ref"] = "0x" + "f" * 64
    with pytest.raises(tclk_pilot_reveal.RevealPrepareError, match="reveal_bridge_failed"):
        tclk_pilot_reveal._run_bridge(wrong)
