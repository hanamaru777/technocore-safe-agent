import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest


PAYER = "did:key:z6Mk" + "f" * 44
PAYEE = "did:key:z6Mk" + "g" * 44
THIRD = "did:key:z6Mk" + "h" * 44
PREFIX = "tclk1 "
BRIDGE = Path("tools/tclk_verify_terminal.mjs")


def _ts(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, UTC).isoformat()


def _decode_line(line: str) -> dict:
    assert line.startswith(PREFIX)
    return json.loads(line[len(PREFIX):])


def _encode_line(frame: dict) -> str:
    return PREFIX + json.dumps(frame, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


@pytest.fixture(scope="module")
def bundle():
    source = r"""
import {makeOffer,makeAccept,encodeFrame,encodePaperRecord,generateHashLock,dealRoom} from '@flop-labs/tclk';
let raw=''; for await (const c of process.stdin) raw += c; const i=JSON.parse(raw);
const now=Date.now(); const minted=generateHashLock();
const offer=makeOffer({from:i.payer,role:'payer',amount:'1000',asset:'PAPER',lock:'hash',rails:['paper'],claimByMs:now+3600000,refundAfterMs:now+7200000,expiresMs:now+600000,job:{proto:'a2a',id:'job-1'},nonce:'0011223344556677'});
const accept=makeAccept(offer,{from:i.payee,statement:minted.hash,nonce:'8899aabbccddeeff'});
const lock={type:'lock',from:i.payer,contract:accept.contract,rail:'paper',ref:accept.contract};
const reveal={type:'reveal',from:i.payee,contract:accept.contract,['se'+'cret']:minted.preimage};
const receipt={type:'receipt',from:i.payer,contract:accept.contract,outcome:'claimed',rail:'paper',ref:accept.contract};
const paper=encodePaperRecord({status:'claimed',lock:'hash',statement:accept.statement,refundAfterMs:offer.refundAfterMs,['se'+'cret']:minted.preimage});
process.stdout.write(JSON.stringify({offer:encodeFrame(offer),accept:encodeFrame(accept),lock:encodeFrame(lock),reveal:encodeFrame(reveal),receipt:encodeFrame(receipt),paper,contract:accept.contract,room:dealRoom(accept.contract),now}));
"""
    built = subprocess.run(
        ["node", "--input-type=module", "--eval", source],
        input=json.dumps({"payer": PAYER, "payee": PAYEE}),
        text=True,
        capture_output=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr
    return json.loads(built.stdout)


def _request(bundle: dict) -> dict:
    now = bundle["now"]
    return {
        "offer_line": bundle["offer"],
        "accept_line": bundle["accept"],
        "accept_timestamp_ms": now,
        "contract_id": bundle["contract"],
        "deal_room": bundle["room"],
        "deal_records": [
            {"seq": 1, "ts": _ts(now + 1000), "from": PAYER, "text": bundle["lock"]},
            {"seq": 2, "ts": _ts(now + 2000), "from": PAYEE, "text": bundle["reveal"]},
            {"seq": 3, "ts": _ts(now + 3000), "from": PAYER, "text": bundle["receipt"]},
        ],
        "paper_note_value": bundle["paper"],
    }


def _run(request: dict):
    return subprocess.run(
        ["node", str(BRIDGE)],
        input=json.dumps(request),
        text=True,
        capture_output=True,
        check=False,
    )


def test_wrong_reveal_party_cannot_complete(bundle):
    request = _request(bundle)
    reveal = _decode_line(bundle["reveal"])
    reveal["from"] = THIRD
    request["deal_records"][1]["from"] = THIRD
    request["deal_records"][1]["text"] = _encode_line(reveal)
    assert _run(request).returncode != 0


def test_wrong_reveal_contract_cannot_complete(bundle):
    request = _request(bundle)
    reveal = _decode_line(bundle["reveal"])
    reveal["contract"] = "0x" + "a" * 64
    request["deal_records"][1]["text"] = _encode_line(reveal)
    assert _run(request).returncode != 0


def test_wrong_paper_lock_ref_cannot_complete(bundle):
    request = _request(bundle)
    lock = _decode_line(bundle["lock"])
    lock["ref"] = "0x" + "b" * 64
    request["deal_records"][0]["text"] = _encode_line(lock)
    assert _run(request).returncode != 0


def test_mismatched_reveal_secret_cannot_complete(bundle):
    request = _request(bundle)
    reveal = _decode_line(bundle["reveal"])
    reveal["secret"] = "0x" + "22" * 32
    request["deal_records"][1]["text"] = _encode_line(reveal)
    assert _run(request).returncode != 0


def test_incomplete_locked_transcript_cannot_complete(bundle):
    request = _request(bundle)
    request["deal_records"] = request["deal_records"][:1]
    assert _run(request).returncode != 0


def test_forged_transport_identity_for_reveal_cannot_complete(bundle):
    request = _request(bundle)
    request["deal_records"][1]["from"] = THIRD
    assert _run(request).returncode != 0


def test_invalid_receipt_is_not_bound_or_synthesized(bundle):
    request = _request(bundle)
    receipt = _decode_line(bundle["receipt"])
    receipt["from"] = THIRD
    request["deal_records"][2]["from"] = THIRD
    request["deal_records"][2]["text"] = _encode_line(receipt)
    checked = _run(request)
    assert checked.returncode == 0, checked.stderr
    output = json.loads(checked.stdout)
    assert output["status"] == "claimed"
    assert output["receipt"] is None
