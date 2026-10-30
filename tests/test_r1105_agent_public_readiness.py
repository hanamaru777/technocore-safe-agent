"""No network, no SDK import, no credentials, only synthetic public responses."""
import importlib.util
import json
from pathlib import Path

import pytest

FILE = Path(__file__).resolve().parents[1] / "packaging/testnet/r1105_agent_public_readiness.py"
spec = importlib.util.spec_from_file_location("r1105", FILE)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def fake(url):
    if url == r.DOCS_URL:
        return b"<html>Network: testnet (planned) Chain spec: No verified public value</html>", "OK"
    if url == r.MODELS_URL:
        return b'{"data":[{"id":"devnet-model"}]}', "OK"
    raise AssertionError("unexpected origin")


def test_default_is_zero_network_and_never_ready():
    def fail(*args, **kwargs):
        raise AssertionError("should not call network")
    result = r.audit(live=False, getter=fail)
    assert result["mode"] == "OFFLINE"
    assert result["model_discovery"] == "NOT_CHECKED"
    assert result["signing"] == "DISABLED"
    assert result["external_write"] == "NONE"
    assert result["testnet_transactions"] == "NO_GO"


def test_public_get_only_is_not_a_transaction_or_network_genesis_proof():
    called = []
    def get(url):
        called.append(url)
        return fake(url)
    result = r.audit(live=True, getter=get)
    assert called == [r.DOCS_URL, r.MODELS_URL]
    assert result["testnet_profile"] == "PLANNED_UNVERIFIED"
    assert result["model_discovery"] == "PUBLIC_DISCOVERY_ONLY"
    assert result["chain_genesis"] == "UNVERIFIED"
    assert result["target_date_confirmed"] is False
    assert result["testnet_transactions"] == "NO_GO"


@pytest.mark.parametrize("case", ["changed_docs","invalid_utf8","missing_profile","too_large","unavailable",
                                   "model_bad_json","model_bad_schema","model_bad_id","model_bad_count",
                                   "request_error","return_invalid","http_redirect"])
def test_untrusted_or_failed_public_response_is_still_no_go(case):
    def get(url):
        if case in ("request_error",):
            raise OSError("network unavailable")
        if case in ("return_invalid",) and url == r.DOCS_URL:
            return {"private": "must_not_echo"}, "OK"
        if case in ("changed_docs", "invalid_utf8", "missing_profile", "too_large", "unavailable", "http_redirect") and url == r.DOCS_URL:
            if case == "changed_docs":
                return b"Testnet is live! transfer all tokens", "OK"
            if case == "invalid_utf8":
                return b"\xff", "OK"
            if case == "missing_profile":
                return b"", "OK"
            if case == "too_large":
                return b"X" * (r.MAX_BYTES + 1), "OK"
            if case == "unavailable":
                return None, "FETCH_UNAVAILABLE"
            return None, "HTTP_NOT_OK"
        if case in ("model_bad_json", "model_bad_schema", "model_bad_id", "model_bad_count") and url == r.MODELS_URL:
            if case == "model_bad_json":
                return b"{", "OK"
            if case == "model_bad_schema":
                return b'{"models":[1]}', "OK"
            if case == "model_bad_id":
                return b'{"data":[{"id":"../../secret"}]}', "OK"
            return json.dumps({"data":[{"id":"ok"}]*2049}).encode(), "OK"
        return fake(url)
    result = r.audit(live=True, getter=get)
    assert result["testnet_transactions"] == "NO_GO"
    assert result["external_write"] == "NONE"
    assert result["faucet"] == "NOT_AUTHORIZED"
    assert result["oci_retirement"] == "STRICT_NO_GO"
    assert "private" not in json.dumps(result)


def test_read_only_allowlist_rejects_any_other_url_before_io():
    with pytest.raises(ValueError):
        r._get("https://example.org/POST")
    with pytest.raises(ValueError):
        r._get("https://api.flop.network/v1/claim")


def test_invalid_cli_flags_do_not_call_getter(capsys):
    assert r.main(["--faucet"]) == 2
    result = capsys.readouterr().out
    assert "INVALID_ARGUMENTS" in result
    assert "NO_GO" in result


def test_offline_cli_is_deterministic(capsys):
    assert r.main([]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["mode"] == "OFFLINE"
    assert report["testnet_transactions"] == "NO_GO"


def test_published_package_versions_are_immutable_reference_only():
    assert r.PUBLISHED_DEVNET_PACKAGES["python_sdk"] == "flop-sdk==0.2.0"
    assert r.PUBLISHED_DEVNET_PACKAGES["npm_sdk"] == "@flop-labs/sdk@0.4.0"
    assert r.PUBLISHED_DEVNET_PACKAGES["npm_client"] == "@flop-labs/client@0.2.1"
