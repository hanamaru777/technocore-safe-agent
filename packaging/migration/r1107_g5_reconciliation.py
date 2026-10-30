"""Five ORIGINAL route adapters and retained-positive, GET-only reconciliation.

No receipt creation, nonce allocation, signing, POST or inference of historical
absence. Private original bytes in; only redacted report() out. A retained
positive is NOT complete G5 finality, and claim CAS is distinct from reveal POST.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from datetime import datetime
from pathlib import Path
import re
import ssl
import sys
import urllib.request

spec = importlib.util.spec_from_file_location("flop_r1107_contract", Path(__file__).with_name("r1107_contract.py"))
C = sys.modules.get(spec.name)
if C is None:
    C = importlib.util.module_from_spec(spec); sys.modules[spec.name] = C; spec.loader.exec_module(C)
E = C.legacy("r1106_technocore_export_readonly.py")
OLD = C.legacy("r1103_g5_receipt_consistency.py")
public_record = C.V
close_call = None


def protocol():
    # Only the actual private reconciliation API needs app verification helpers.
    # Dry-run does not import core, signer or ambient application state.
    global close_call
    if close_call is None:
        from flop_agent import close_call as terms
        close_call = terms

ROUTES = OLD.ROUTES
MAX_RECORDS = OLD.MAX_RECORDS
ACCEPT_FIELDS = "schema_version state stage_id approval_digest offer_id accept_line accept_sha256 contract_id deal_room did nonce sig prepared_at attempted_at posted_at seq ts last_error git_commit_sha executed_at"
REVEAL_FIELDS = "schema_version state stage_id approval_digest offer_id contract_id deal_room did reveal_sha256 nonce sig prepared_at reveal_attempted_at reveal_posted_at reveal_seq reveal_ts claim_attempted_at claimed_at locked_note_sha256 claimed_note_sha256 last_error git_commit_sha executed_at"


def ledger_digest(files, inventory=None):
    C.need(type(files) is dict and 0 < len(files) <= C.R.T.MAX_ARCHIVE_ENTRIES, "LEDGER_BOUND_STOP")
    for name, raw in files.items():
        path = C.R.T.relative("state/" + name)
        C.need(str(path).replace("\\", "/") == "state/" + name)
        C.raw_hash(raw)
    hashes = {k: C.raw_hash(v) for k, v in sorted(files.items())}
    if inventory is not None:
        C.need(type(inventory) is dict and len(inventory) <= C.R.T.MAX_ARCHIVE_ENTRIES, "LEDGER_BOUND_STOP")
        for k, v in inventory.items():
            C.R.T.relative("state/" + k); C.digest(v)
        C.need(all(inventory.get(k) == v for k, v in hashes.items()), "LEDGER_DIGEST_STOP")
        # Large observer data need not be loaded in RAM; its full content hash
        # remains bound. All receipt/fence/approval/pending sidecars MUST load.
        required = {k for k in inventory if k.startswith(("signer/", "autopilot/", "close1/")) or
                    k in ("nonces.json", "activities.jsonl", "verified-did.json")}
        C.need(required <= set(files), "LOCAL_SIDECAR_MISSING")
        hashes = inventory
    return C.G.sha(hashes)


def _object(files, name):
    C.need(name in files, "LOCAL_SIDECAR_MISSING")
    value = C.decode(files[name])
    C.need(type(value) is dict, "LOCAL_SCHEMA_STOP")
    return value


def _record(route, identity, value, room, *, text_hash=None, sig=None, leg=0, terms=None, maker_sig=None):
    did, nonce = value.get("did", value.get("owner_did")), value.get("nonce")
    C.need(type(did) is str and public_record.DID_RE.fullmatch(did), "LOCAL_DID_STOP")
    C.need(type(nonce) is str and public_record.NONCE_RE.fullmatch(nonce), "LOCAL_NONCE_STOP")
    C.need(type(room) is str and public_record.ROOM_RE.fullmatch(room), "LOCAL_ROOM_STOP")
    if text_hash is not None: C.digest(text_hash)
    if sig is not None: C.need(type(sig) is str and public_record.SIG_RE.fullmatch(sig), "LOCAL_SIGNATURE_STOP")
    return {"route": route, "id": identity, "leg": leg, "did": did, "room": room, "nonce": nonce,
            "text_hash": text_hash, "sig": sig, "state": value.get("state", value.get("status", "attempting")),
            "seq": value.get("seq", value.get("reveal_seq")), "terms": terms, "maker_sig": maker_sig,
            "permanent_no_retry": route in ROUTES[3:]}


def original_attempts(files, own_did):
    """Interpret actual original sidecars, never a caller's generic ACCEPTED row.

    Oracle text hash comes from its durable prepared receipt; room from original
    outbox. TCLK accept/reveal use their own stored text/hash/signature. Close1
    binds permanent fence+raw approval digest+each original leg's terms. Missing
    historical approvals are UNKNOWN, not reconstructed from current templates.
    """
    protocol()
    ledger_digest(files)
    result = {r: [] for r in ROUTES}
    receipts = _object(files, "signer/oracle-signer-receipts.json")
    outbox = _object(files, "autopilot/autopilot-outbox.json")
    C.need(receipts.get("schema_version") == 1 and type(receipts.get("receipts")) is dict and
           type(outbox.get("outbox")) is dict, "LOCAL_SCHEMA_STOP")
    for identity, value in receipts["receipts"].items():
        C.need(type(identity) is str and re.fullmatch(r"[0-9a-f]{20}", identity), "LOCAL_SCHEMA_STOP")
        intent = outbox["outbox"].get(identity)
        C.need(type(intent) is dict and value["state"] in ("prepared", "posted", "acknowledged"), "LOCAL_SIDECAR_MISSING")
        item = _record(ROUTES[0], identity, value, intent["room"], text_hash=value["text_hash"])
        item["receipt_hash"] = C.digest(value["receipt_hash"])
        result[ROUTES[0]].append(item)
    for name in sorted(files):
        if re.fullmatch(r"signer/tclk-pilot-accepts/[0-9a-f]{32}\.json", name):
            v = _object(files, name)
            C.shape(v, ACCEPT_FIELDS)
            C.need(v["state"] in ("prepared", "attempting", "ambiguous", "posted") and
                   name.endswith(v["stage_id"] + ".json"), "LOCAL_SCHEMA_STOP")
            C.need(C.raw_hash(v["accept_line"].encode()) == v["accept_sha256"], "LOCAL_PAYLOAD_STOP")
            result[ROUTES[1]].append(_record(ROUTES[1], v["stage_id"], v, "tclk-offers",
                text_hash=v["accept_sha256"], sig=v["sig"]))
        elif re.fullmatch(r"signer/tclk-pilot-reveal-publishes/[0-9a-f]{32}\.json", name):
            v = _object(files, name)
            C.shape(v, REVEAL_FIELDS)
            C.need(v["state"] in ("prepared", "reveal_attempting", "reveal_ambiguous", "reveal_posted",
                                  "claim_attempting", "claim_ambiguous", "claimed") and
                   name.endswith(v["stage_id"] + ".json"), "LOCAL_SCHEMA_STOP")
            item = _record(ROUTES[2], v["stage_id"], v, v["deal_room"], text_hash=v["reveal_sha256"], sig=v["sig"])
            item["auxiliary_claim"] = "NOT_PROVEN"  # room export cannot attest note CAS finality
            result[ROUTES[2]].append(item)
        elif re.fullmatch(r"signer/close1-attempt-[0-9a-f]{64}\.json", name):
            v = _object(files, name)
            batch = v.get("batch") is True
            route = ROUTES[4] if batch else ROUTES[3]
            approval_name = "signer/close1-approved-batch.json" if batch else "signer/close1-approved-trade.json"
            approval = _object(files, approval_name)
            C.need(C.raw_hash(files[approval_name]) == v["approval_sha256"], "HISTORICAL_APPROVAL_MISSING")
            legs = approval["legs"] if batch else [approval]
            C.need(type(legs) is list and 0 < len(legs) <= MAX_RECORDS, "LOCAL_SCHEMA_STOP")
            matches = [(i, x) for i, x in enumerate(legs) if x["trade_id"] == v["trade_id"]]
            C.need(len(matches) == 1, "LOCAL_LEG_STOP")
            index, leg = matches[0]
            C.need(name == "signer/close1-attempt-" + hashlib.sha256(v["trade_id"].encode()).hexdigest() + ".json"
                   and v["room"] == "close1", "LOCAL_FENCE_STOP")
            terms = {"id": leg["trade_id"], "maker": leg["maker"], "side": leg["maker_side"],
                     "qty": leg["qty"], "px": leg["px"], "until": leg["until"], "taker": "any"}
            close_call.canonical_terms(terms)
            receipt_name = name.replace("close1-attempt-", "close1-receipt-")
            if receipt_name in files:
                receipt = _object(files, receipt_name)
                C.need(all(receipt.get(k) == x for k, x in v.items()) and receipt.get("status") == "posted", "LOCAL_RECEIPT_STOP")
                v = receipt
            result[route].append(_record(route, leg["trade_id"], v, "close1", leg=index, terms=terms, maker_sig=leg["maker_sig"]))
    nonces, ids = set(), set()
    counter = _object(files, "nonces.json")
    for route, rows in result.items():
        C.need(len(rows) <= MAX_RECORDS, "LOCAL_BOUND_STOP")
        for item in rows:
            C.need(item["did"] == own_did, "DID_BINDING_STOP")
            identity = item["did"], item["room"], item["nonce"]
            attempt = route, item["id"], item["leg"]
            C.need(identity not in nonces and attempt not in ids, "DUPLICATE_ATTEMPT_STOP")
            C.need(type(counter.get(item["did"] + "|" + item["room"])) is int and
                   counter[item["did"] + "|" + item["room"]] >= int(item["nonce"]), "NONCE_HISTORY_STOP")
            nonces.add(identity); ids.add(attempt)
    return result


def fetch_retained(room):
    """Actual bounded public TLS GET, never invoked by readiness/default CLI."""
    C.need(type(room) is str and E.ROOM.fullmatch(room) and not room.startswith("p-"), "PUBLIC_ROOM_STOP")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), E._NoRedirect())
    request = urllib.request.Request(E.HOST + "/r/" + room + "/export", method="GET",
                                   headers={"Accept": "application/x-ndjson", "Cache-Control": "no-cache"})
    try:
        values = []
        for _ in range(2):
            with opener.open(request, timeout=15) as response:
                C.need(response.status == 200, "UPSTREAM_READ_STOP")
                pair = response.read(E.MAX_BYTES + 1), response.headers.get("X-Room-Generation")
            E.parse_export(*pair)
            values.append(pair)
        C.need(values[0] == values[1], "EXPORT_GENERATION_RACE")
        # Still retained-only: the official generation stamp has a residual
        # race. No endpoint here certifies historical absence or full finality.
        return values[0]
    except (OSError, ValueError):
        raise C.Stop("UPSTREAM_READ_STOP") from None


def reconcile(files, own_did, guard, exports, witnesses, enrollment, *, now, inventory=None):
    """exports: private room->(byte-exact JSONL, generation), signed externally.

    The caller owns raw evidence custody. This function never signs a summary
    or replaces it with a fabricated negative. Missing/empty/ring-only records
    remain unknown. It returns no body, nonce, full DID, room or private paths.
    """
    held = guard.guard(now=now)
    digest = ledger_digest(files, inventory)
    C.need(held["ledger_digest"] == digest and C.raw_hash(own_did.encode()) == enrollment.context["did"], "EPOCH_BINDING_STOP")
    attempts = original_attempts(files, own_did)
    result = []
    used_seq = set()
    for route in ROUTES:
        matched = 0
        rows = attempts[route]
        for item in rows:
            room = item["room"]
            C.need(room in exports and room in witnesses, "UPSTREAM_UNAVAILABLE")
            raw, generation = exports[room]
            E.parse_export(raw, generation)
            proof = enrollment.verify(witnesses[room], "retained-export", "upstream", now)
            C.need(proof == {"room_digest": C.raw_hash(room.encode()), "export_digest": C.raw_hash(raw),
                   "generation": generation, "epoch": held["epoch"], "ledger_digest": digest,
                   "source": "https://technocore.chat/r/{room}/export", "semantics": "RETAINED_POSITIVE_ONLY"},
                   "UPSTREAM_BINDING_STOP")
            public = [C.decode(line) for line in raw.splitlines()]
            own_nonces = set()
            for row in public:
                if row.get("from") == own_did:
                    public_record.verify_signed_record(room, row)
                    C.need(type(row.get("ts")) is str and
                           datetime.fromisoformat(row["ts"].replace("Z", "+00:00")).utcoffset() is not None,
                           "UPSTREAM_TIME_STOP")
                    n = str(row.get("nonce"))
                    C.need(n not in own_nonces, "DUPLICATE_UPSTREAM_NONCE")
                    own_nonces.add(n)
            found = [r for r in public if r.get("from") == own_did and str(r.get("nonce")) == item["nonce"]]
            if not found:
                continue  # Never infer absence from retained ring, even if contiguous.
            C.need(len(found) == 1, "DUPLICATE_UPSTREAM_STOP")
            row = found[0]
            C.need((room, row["seq"]) not in used_seq, "DUPLICATE_UPSTREAM_STOP")
            C.need(item["seq"] is None or type(item["seq"]) is int and item["seq"] == row["seq"], "RECEIPT_SEQUENCE_STOP")
            if item["text_hash"]:
                C.need(C.raw_hash(row["text"].encode()) == item["text_hash"], "PAYLOAD_MISMATCH")
            if item["sig"]: C.need(row["sig"] == item["sig"], "SIGNATURE_MISMATCH")
            if item["terms"]:
                trade = C.decode(row["text"].encode())
                C.need(trade.get("terms") == item["terms"] and trade.get("taker") == own_did and
                       trade.get("t") == "trade" and trade.get("season") == close_call.CONTEST_ID and
                       trade.get("maker_sig") == item["maker_sig"], "TRADE_BINDING_STOP")
                public_record.verify_did_signature(item["terms"]["maker"], trade["maker_sig"], close_call.maker_signature_preimage(item["terms"]))
                public_record.verify_did_signature(own_did, trade["taker_sig"], close_call.taker_signature_preimage(item["terms"], own_did))
            if route == ROUTES[0]:
                expected = hashlib.sha256(f"{item['id']}|{own_did}|{item['nonce']}|{row['text']}".encode()).hexdigest()
                C.need(expected == item["receipt_hash"], "LOCAL_RECEIPT_STOP")
            used_seq.add((room, row["seq"])); matched += 1
        result.append({"route": route, "known_attempts": len(rows), "retained_positive_matches": matched,
                       "unresolved_known": len(rows) - matched, "retry_authority": "NONE",
                       "history_complete": False, "auxiliary_claim_finality": "NOT_PROVEN" if route == ROUTES[2] else "NOT_APPLICABLE"})
    C.need(guard.guard(now=now) == held, "EPOCH_CHANGED")
    return {**C.decisions("G5_NOT_PROVABLE_FROM_RETAINED_HISTORY"), "G5": "NO_GO", "routes": result,
            "epoch_digest": held["epoch"], "ledger_digest": digest, "negative_finality": "UNSUPPORTED_BY_OFFICIAL_READ_API"}
