"""Synthetic data only. No POST, upstream API, state or production credentials."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import pytest

FILE = Path(__file__).resolve().parents[1] / "packaging/migration/r1103_g5_receipt_consistency.py"
spec = importlib.util.spec_from_file_location("r1103_g5", FILE)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def h(s):
    return hashlib.sha256(s.encode()).hexdigest()


def fixture():
    routes = {}
    for i, route in enumerate(r.ROUTES):
        values = {"room_sha256": h("room-" + route), "did_sha256": h("did"),
                  "nonce_sha256": h("nonce-" + route), "text_sha256": h("text-" + route)}
        routes[route] = {
            "local": [{**values, "attempt_id": h("attempt-" + route), "leg": i, "local_state": "acknowledged"}],
            "upstream": [{**values, "terminal_status": "ACCEPTED", "receipt_sha256": h("receipt-" + route), "server_seq": 123 + i}],
        }
    return {"schema_version": 1, "epoch": h("epoch"), "routes": routes}


def test_even_five_consistent_synthetic_records_are_not_g5_or_cutover():
    result = r.assess(fixture())
    assert result["reason"] == "CONSISTENCY_ONLY_UPSTREAM_AUTHORITY_NOT_PROVEN"
    assert result["route_record_counts"] == [1] * 5
    assert result["five_route_finality"] == "NOT_PROVEN"
    assert result["cutover"] == "NO_GO"
    assert result["oci_retirement"] == "STRICT_NO_GO"
    assert "did" not in str(result) and "nonce" not in str(result)


@pytest.mark.parametrize("route", r.ROUTES)
@pytest.mark.parametrize("kind", ["unknown", "negative", "missing", "wrong_nonce", "duplicate", "no_source", "retrying"])
def test_all_routes_reject_incomplete_untrusted_or_ambiguous_records(route, kind):
    a = fixture()
    row = a["routes"][route]
    if kind == "unknown":
        row["upstream"][0]["terminal_status"] = "UNKNOWN"
    elif kind == "negative":
        row["upstream"][0]["terminal_status"] = "DEFINITELY_NOT_ACCEPTED"
    elif kind == "missing":
        row["upstream"] = []
    elif kind == "wrong_nonce":
        row["upstream"][0]["nonce_sha256"] = h("wrong")
    elif kind == "duplicate":
        row["upstream"].append(copy.deepcopy(row["upstream"][0]))
    elif kind == "no_source":
        row["local"] = []
    else:
        row["local"][0]["local_state"] = "retrying"
    result = r.assess(a)
    assert result["reason"] != "CONSISTENCY_ONLY_UPSTREAM_AUTHORITY_NOT_PROVEN"
    assert result["five_route_finality"] == "NOT_PROVEN"
    assert result["route_record_counts"] is None


@pytest.mark.parametrize("what", ["missing_route", "duplicate_nonce", "duplicate_attempt", "bool_seq", "wrong_keys", "bad_epoch"])
def test_global_binding_and_schema_fail_closed(what):
    a = fixture()
    route0, route1 = r.ROUTES[:2]
    if what == "missing_route":
        del a["routes"][route0]
    elif what == "duplicate_nonce":
        a["routes"][route1]["local"][0]["nonce_sha256"] = a["routes"][route0]["local"][0]["nonce_sha256"]
        a["routes"][route1]["local"][0]["room_sha256"] = a["routes"][route0]["local"][0]["room_sha256"]
        a["routes"][route1]["upstream"][0]["nonce_sha256"] = a["routes"][route0]["upstream"][0]["nonce_sha256"]
        a["routes"][route1]["upstream"][0]["room_sha256"] = a["routes"][route0]["upstream"][0]["room_sha256"]
    elif what == "duplicate_attempt":
        a["routes"][route1]["local"][0]["attempt_id"] = a["routes"][route0]["local"][0]["attempt_id"]
        a["routes"][route1]["local"][0]["leg"] = a["routes"][route0]["local"][0]["leg"]
    elif what == "bool_seq":
        a["routes"][route0]["upstream"][0]["server_seq"] = True
    elif what == "wrong_keys":
        a["routes"][route0]["upstream"][0]["raw_nonce"] = "unsafe"
    else:
        a["epoch"] = "broken"
    assert r.assess(a)["reason"] != "CONSISTENCY_ONLY_UPSTREAM_AUTHORITY_NOT_PROVEN"
