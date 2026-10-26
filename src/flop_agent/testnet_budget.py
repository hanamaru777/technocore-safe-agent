"""R1060: purely offline agent inference budget/idempotency kernel.

NOT a FLOP transport, signer, faucet, or receipt verifier. Operator-configured
units are synthetic accounting units and NEVER imply $FLOP denominations.
No live testnet request is permitted by this module or its output.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import date
import re

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
ID = re.compile(r"[a-z0-9-]{8,64}\Z")
TASKS = frozenset({"public_news_summary", "public_market_analysis",
                   "public_document_summary"})
STATUSES = frozenset({"PREPARED", "UNKNOWN_POST", "CANCELLED_NO_SEND"})
MAX_ITEMS = 512
MAX_UNITS = 10**12
JOB_FIELDS = frozenset({"intent_id", "utc_day", "task_class", "data_class",
                        "payload_sha256", "max_test_units"})
ROW_FIELDS = frozenset((*JOB_FIELDS, "status", "unverified_receipt_sha256"))
CAP_FIELDS = frozenset({"max_request_units", "max_day_units", "max_total_units"})


class Stop(Exception):
    """Fixed reason only; no private parameters or payloads."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise Stop(code)


def integer(value, code):
    need(type(value) is int and 1 <= value <= MAX_UNITS, code)
    return value


def caps(policy):
    need(type(policy) is dict and set(policy) == CAP_FIELDS,
         "POLICY_SCHEMA_STOP")
    clean = {key: integer(policy[key], "POLICY_UNITS_STOP")
             for key in CAP_FIELDS}
    need(clean["max_request_units"] <= clean["max_day_units"] <=
         clean["max_total_units"], "POLICY_ORDER_STOP")
    return clean


def valid_job(job):
    need(type(job) is dict and set(job) == JOB_FIELDS, "JOB_SCHEMA_STOP")
    need(type(job["intent_id"]) is str and ID.fullmatch(job["intent_id"]),
         "JOB_ID_STOP")
    need(type(job["payload_sha256"]) is str and
         HEX64.fullmatch(job["payload_sha256"]), "JOB_HASH_STOP")
    need(type(job["task_class"]) is str and job["task_class"] in TASKS,
         "JOB_CLASS_STOP")
    need(type(job["data_class"]) is str and job["data_class"] == "PUBLIC",
         "PRIVATE_INPUT_STOP")
    need(type(job["utc_day"]) is str and
         re.fullmatch(r"\d{4}-\d{2}-\d{2}", job["utc_day"]) is not None,
         "DAY_FORMAT_STOP")
    try:
        need(date.fromisoformat(job["utc_day"]).isoformat() == job["utc_day"],
             "DAY_FORMAT_STOP")
    except ValueError:
        raise Stop("DAY_FORMAT_STOP") from None
    integer(job["max_test_units"], "JOB_UNITS_STOP")


def validate_ledger(ledger):
    need(type(ledger) is dict and set(ledger) == {"schema_version", "items"} and
         type(ledger["schema_version"]) is int and ledger["schema_version"] == 1 and
         type(ledger["items"]) is list and len(ledger["items"]) <= MAX_ITEMS,
         "LEDGER_SCHEMA_STOP")
    seen = set()
    for row in ledger["items"]:
        need(type(row) is dict and set(row) == ROW_FIELDS, "ROW_SCHEMA_STOP")
        job = {k: row[k] for k in JOB_FIELDS}
        valid_job(job)
        need(row["intent_id"] not in seen, "DUPLICATE_INTENT_STOP")
        seen.add(row["intent_id"])
        need(type(row["status"]) is str and row["status"] in STATUSES,
             "ROW_STATUS_STOP")
        evidence = row["unverified_receipt_sha256"]
        need(evidence is None or type(evidence) is str and HEX64.fullmatch(evidence),
             "ROW_EVIDENCE_STOP")
        need(row["status"] != "PREPARED" or evidence is None,
             "ROW_PRE_SEND_EVIDENCE_STOP")
        need(row["status"] != "CANCELLED_NO_SEND" or evidence is None,
             "ROW_CANCEL_EVIDENCE_STOP")


def new_ledger():
    return {"schema_version": 1, "items": []}


def committed_units(ledger, utc_day):
    # UNKNOWN_POST is NOT automatically refunded. No blind replays.
    rows = [r for r in ledger["items"] if r["status"] != "CANCELLED_NO_SEND"]
    return (sum(r["max_test_units"] for r in rows),
            sum(r["max_test_units"] for r in rows if r["utc_day"] == utc_day))


def prepare(ledger, policy, job):
    """Return a new proposed state, not a durable authorization to POST."""
    validate_ledger(ledger)
    c = caps(policy)
    valid_job(job)
    need(len(ledger["items"]) < MAX_ITEMS, "LEDGER_FULL_STOP")
    need(not any(row["intent_id"] == job["intent_id"]
                 for row in ledger["items"]), "DUPLICATE_INTENT_STOP")
    need(job["max_test_units"] <= c["max_request_units"], "REQUEST_CAP_STOP")
    total, daily = committed_units(ledger, job["utc_day"])
    need(daily + job["max_test_units"] <= c["max_day_units"],
         "DAILY_CAP_STOP")
    need(total + job["max_test_units"] <= c["max_total_units"],
         "TOTAL_CAP_STOP")
    value = deepcopy(ledger)
    value["items"].append({**job, "status": "PREPARED",
                           "unverified_receipt_sha256": None})
    return value


def transition(ledger, intent_id, action, evidence_sha256=None):
    """Model only: caller must use a separate durable pre-send fence.

    UNKNOWN_POST is terminal for further attempts, even after unverified
    evidence arrives. An authenticated FLOP protocol receipt verifier is
    required before any authoritative settlement accounting or retry.
    """
    validate_ledger(ledger)
    need(type(intent_id) is str and ID.fullmatch(intent_id), "INTENT_ID_STOP")
    need(action in ("MARK_ATTEMPTED", "CANCEL_BEFORE_SEND", "NOTE_UNVERIFIED_RECEIPT"),
         "ACTION_STOP")
    rows = [i for i, r in enumerate(ledger["items"]) if r["intent_id"] == intent_id]
    need(len(rows) == 1, "INTENT_NOT_FOUND_STOP")
    next_state = deepcopy(ledger)
    row = next_state["items"][rows[0]]
    if action == "MARK_ATTEMPTED":
        need(evidence_sha256 is None and row["status"] == "PREPARED",
             "DUPLICATE_OR_AMBIGUOUS_SEND_STOP")
        row["status"] = "UNKNOWN_POST"
    elif action == "CANCEL_BEFORE_SEND":
        need(evidence_sha256 is None and row["status"] == "PREPARED",
             "CANCEL_AFTER_SEND_STOP")
        row["status"] = "CANCELLED_NO_SEND"
    else:
        need(row["status"] == "UNKNOWN_POST" and
             row["unverified_receipt_sha256"] is None and
             type(evidence_sha256) is str and
             HEX64.fullmatch(evidence_sha256), "UNVERIFIED_RECEIPT_STOP")
        row["unverified_receipt_sha256"] = evidence_sha256
    return next_state


def redacted_report(ledger, policy):
    validate_ledger(ledger)
    caps(policy)
    return {
        "schema_version": 1,
        "offline_intents": len(ledger["items"]),
        "unknown_post_count": sum(r["status"] == "UNKNOWN_POST"
                                  for r in ledger["items"]),
        "canceled_without_send_count": sum(r["status"] == "CANCELLED_NO_SEND"
                                          for r in ledger["items"]),
        "official_network_release_verified": "NO",
        "external_receipt_authenticity_verified": "NO",
        "faucet_or_inference_live_permission": "NO",
        "persisted_attempt_fence": "NOT_IMPLEMENTED",
        "original_did_custody": "NOT_PROVEN",
        "official_testnet_score": "NOT_PROVEN",
        "oci_retirement": "STRICT_NO_GO",
    }
