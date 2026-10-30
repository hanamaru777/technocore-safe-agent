"""R1103 pure OFFLINE five-route source/upstream receipt consistency precheck.

Untrusted input does NOT prove a remote read, issuer authenticity, terminal
negative, absence of unknown posts, writer fencing, source epoch, or G5.
No I/O, credentials, import side-effects, network calls or mutation.
"""
from __future__ import annotations

import re

ROUTES = (
    "flop_agent.oracle_signer",
    "flop_agent.tclk_pilot_accept",
    "flop_agent.tclk_pilot_reveal_publish",
    "flop_agent.close1_approved_trade",
    "flop_agent.close1_batch_trade",
)
HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_RECORDS = 2048
LOCAL_STATES = frozenset(("prepared", "attempting", "posted", "acknowledged", "ambiguous", "quarantined"))


class Stop(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Stop(code)


def exact(obj, keys, code="SCHEMA_STOP"):
    require(type(obj) is dict and set(obj) == set(keys.split()), code)


def hash_field(x):
    require(type(x) is str and HEX.fullmatch(x), "IDENTITY_STOP")


def bounded_int(x, low, high):
    require(type(x) is int and low <= x <= high, "NUMBER_STOP")


def _identity(row):
    return tuple(row[k] for k in ("room_sha256", "did_sha256", "nonce_sha256", "text_sha256"))


def _check_local(row):
    exact(row, "attempt_id leg room_sha256 did_sha256 nonce_sha256 text_sha256 local_state")
    for k in ("attempt_id", "room_sha256", "did_sha256", "nonce_sha256", "text_sha256"):
        hash_field(row[k])
    bounded_int(row["leg"], 0, MAX_RECORDS)
    require(type(row["local_state"]) is str and row["local_state"] in LOCAL_STATES, "STATE_STOP")


def _check_upstream(row):
    exact(row, "room_sha256 did_sha256 nonce_sha256 text_sha256 terminal_status receipt_sha256 server_seq")
    for k in ("room_sha256", "did_sha256", "nonce_sha256", "text_sha256", "receipt_sha256"):
        hash_field(row[k])
    # Merely writing ACCEPTED does not make a response authoritative.
    require(row["terminal_status"] == "ACCEPTED", "UPSTREAM_UNRESOLVED")
    bounded_int(row["server_seq"], 1, 2**63 - 1)


def assess(bundle):
    """Assess deterministic record matching; NEVER produce a production PASS.

    Any result is safe to log: no identifiers, records, room, DID, nonce or
    receipts are echoed. No signed/upstream validation is performed here.
    """
    reason = "UNAUTHENTICATED_INPUT"
    counts = None
    try:
        exact(bundle, "schema_version epoch routes")
        require(type(bundle["schema_version"]) is int and bundle["schema_version"] == 1, "SCHEMA_STOP")
        hash_field(bundle["epoch"])
        routes = bundle["routes"]
        require(type(routes) is dict and set(routes) == set(ROUTES), "FIVE_ROUTE_STOP")
        attempts = set()
        nonces = set()
        totals = []
        for route in ROUTES:
            item = routes[route]
            exact(item, "local upstream")
            local, upstream = item["local"], item["upstream"]
            require(type(local) is list and type(upstream) is list and
                    0 < len(local) <= MAX_RECORDS and len(local) == len(upstream), "UPSTREAM_COMPLETENESS_STOP")
            local_by_id, upstream_by_id = {}, {}
            for entry in local:
                _check_local(entry)
                identity = _identity(entry)
                attempt_key = (entry["attempt_id"], entry["leg"])
                nonce_key = (entry["did_sha256"], entry["room_sha256"], entry["nonce_sha256"])
                require(identity not in local_by_id and attempt_key not in attempts and
                        nonce_key not in nonces, "DUPLICATE_ATTEMPT_STOP")
                local_by_id[identity] = entry
                attempts.add(attempt_key)
                nonces.add(nonce_key)
            for entry in upstream:
                _check_upstream(entry)
                identity = _identity(entry)
                require(identity not in upstream_by_id, "DUPLICATE_UPSTREAM_STOP")
                upstream_by_id[identity] = entry
            require(local_by_id.keys() == upstream_by_id.keys(), "UPSTREAM_IDENTITY_STOP")
            totals.append(len(local))
        counts = totals
        # No way to attest actual upstream observation from an offline untrusted
        # mapping. Even the all-matched case remains NOT_PROVEN.
        reason = "CONSISTENCY_ONLY_UPSTREAM_AUTHORITY_NOT_PROVEN"
    except Stop as error:
        reason = str(error)
    except (TypeError, KeyError, OverflowError, RecursionError):
        reason = "SCHEMA_STOP"
    return {
        "phase": "R1103", "result": "OFFLINE_G5_NOT_PROVEN", "reason": reason,
        "route_record_counts": counts, "five_route_finality": "NOT_PROVEN",
        "source_writer_barrier": "NOT_PROVEN", "source_archive": "NOT_AUTHORIZED",
        "cutover": "NO_GO", "oci_retirement": "STRICT_NO_GO",
    }
