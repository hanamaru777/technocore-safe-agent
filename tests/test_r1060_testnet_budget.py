"""R1060 strictly offline, future FLOP testnet synthetic budget regression."""
from copy import deepcopy
import json
import ast
from pathlib import Path
import pytest

from flop_agent import testnet_budget as t

SOURCE = Path(__file__).resolve().parents[1] / "src/flop_agent/testnet_budget.py"


def policy():
    return {"max_request_units": 3, "max_day_units": 5, "max_total_units": 8}


def job(identifier, day="2026-11-03", cost=3):
    return {"intent_id": identifier, "utc_day": day,
            "task_class": "public_news_summary", "data_class": "PUBLIC",
            "payload_sha256": "a"*64, "max_test_units": cost}


def test_three_levels_of_budget_and_immutable_input():
    initial = t.new_ledger()
    first = t.prepare(initial, policy(), job("public-news-01"))
    assert initial["items"] == []
    assert len(first["items"]) == 1
    assert first["items"][0]["status"] == "PREPARED"
    second = t.prepare(first, policy(), job("public-news-02", cost=2))
    assert t.committed_units(second, "2026-11-03") == (5, 5)
    with pytest.raises(t.Stop, match="DAILY_CAP_STOP"):
        t.prepare(second, policy(), job("public-news-03", cost=1))
    third = t.prepare(second, policy(), job("public-news-03", "2026-11-04", 3))
    assert t.committed_units(third, "2026-11-04") == (8, 3)
    with pytest.raises(t.Stop, match="TOTAL_CAP_STOP"):
        t.prepare(third, policy(), job("public-news-04", "2026-11-05", 1))


def test_duplicate_not_allowed_even_if_previous_marked_canceled():
    old = t.prepare(t.new_ledger(), policy(), job("public-news-01"))
    old = t.transition(old, "public-news-01", "CANCEL_BEFORE_SEND")
    with pytest.raises(t.Stop, match="DUPLICATE_INTENT_STOP"):
        t.prepare(old, policy(), job("public-news-01"))


def test_attempt_unknown_never_retries_or_refunds():
    old = t.prepare(t.new_ledger(), policy(), job("public-news-01"))
    sent = t.transition(old, "public-news-01", "MARK_ATTEMPTED")
    assert old["items"][0]["status"] == "PREPARED"
    assert sent["items"][0]["status"] == "UNKNOWN_POST"
    with pytest.raises(t.Stop, match="DUPLICATE_OR_AMBIGUOUS_SEND_STOP"):
        t.transition(sent, "public-news-01", "MARK_ATTEMPTED")
    with pytest.raises(t.Stop, match="CANCEL_AFTER_SEND_STOP"):
        t.transition(sent, "public-news-01", "CANCEL_BEFORE_SEND")
    assert t.committed_units(sent, "2026-11-03") == (3, 3)


def test_unverified_receipt_is_not_equivalent_to_settlement():
    plan = t.prepare(t.new_ledger(), policy(), job("public-news-01"))
    sent = t.transition(plan, "public-news-01", "MARK_ATTEMPTED")
    observed = t.transition(sent, "public-news-01", "NOTE_UNVERIFIED_RECEIPT",
                            "b"*64)
    assert observed["items"][0]["status"] == "UNKNOWN_POST"
    assert t.redacted_report(observed, policy())["external_receipt_authenticity_verified"] == "NO"
    with pytest.raises(t.Stop, match="UNVERIFIED_RECEIPT_STOP"):
        t.transition(observed, "public-news-01", "NOTE_UNVERIFIED_RECEIPT",
                     "c"*64)


@pytest.mark.parametrize(("value", "error"), (
    ({"intent_id": "public-news-01", "utc_day": "2026-11-03",
      "task_class": "public_news_summary", "data_class": "PRIVATE",
      "payload_sha256": "a"*64, "max_test_units": 1}, "PRIVATE_INPUT_STOP"),
    (dict(job("public-news-01"), max_test_units=True), "JOB_UNITS_STOP"),
    (dict(job("public-news-01"), max_test_units=0), "JOB_UNITS_STOP"),
    (dict(job("public-news-01"), utc_day="2026-11-31"), "DAY_FORMAT_STOP"),
    (dict(job("public-news-01"), task_class="arbitrary"), "JOB_CLASS_STOP"),
    (dict(job("public-news-01"), payload_sha256="not-digest"), "JOB_HASH_STOP"),
))
def test_bad_jobs_denied(value, error):
    with pytest.raises(t.Stop, match=error):
        t.prepare(t.new_ledger(), policy(), value)


def test_privacy_and_unvalidated_external_row_deny():
    l = t.prepare(t.new_ledger(), policy(), job("public-news-01"))
    l["items"][0]["status"] = "SETTLED"
    with pytest.raises(t.Stop, match="ROW_STATUS_STOP"):
        t.redacted_report(l, policy())
    a = t.new_ledger()
    a["extra"] = "bypass"
    with pytest.raises(t.Stop, match="LEDGER_SCHEMA_STOP"):
        t.prepare(a, policy(), job("public-news-01"))


def test_no_credit_or_monetary_implication():
    l = t.prepare(t.new_ledger(), policy(), job("public-news-01"))
    r = t.redacted_report(l, policy())
    assert r["official_network_release_verified"] == "NO"
    assert r["faucet_or_inference_live_permission"] == "NO"
    assert r["persisted_attempt_fence"] == "NOT_IMPLEMENTED"
    assert r["official_testnet_score"] == "NOT_PROVEN"
    assert r["original_did_custody"] == "NOT_PROVEN"
    assert r["oci_retirement"] == "STRICT_NO_GO"
    assert "payload_sha256" not in json.dumps(r)


def test_no_io_transport_or_signer():
    tree = ast.parse(SOURCE.read_text("utf8"))
    forbidden = {"connect", "post", "get", "put", "urlopen", "open",
                 "write_text", "write_bytes", "system", "Popen", "run",
                 "rmtree", "remove", "unlink", "sign", "request"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            if isinstance(n.func, ast.Name):
                assert n.func.id not in forbidden
            if isinstance(n.func, ast.Attribute):
                assert n.func.attr not in forbidden
    from flop_agent import testnet
    with pytest.raises(NotImplementedError):
        testnet.unavailable()
