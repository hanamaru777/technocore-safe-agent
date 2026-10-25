"""Synthetic FLOP testnet gate fixtures. Never contacts or writes to FLOP."""
import ast
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "packaging/testnet/r1057_offline_agent_launch_gate.py"
spec = importlib.util.spec_from_file_location("r1057", SOURCE)
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


def packet():
    return {
        "network_state": "NOT_PUBLISHED",
        "chain_id": None,
        "genesis_sha256": None,
        "rpc_url": None,
        "faucet_url": None,
        "inference_url": None,
        "signed_request_spec_sha256": None,
        "settled_receipt_spec_sha256": None,
        "rate_rules_sha256": None,
        "original_did_continuity_attested": False,
        "operator_reviewed_domains": [],
        "formal_operator_source_sha256": None,
    }


def encoded(obj):
    return json.dumps(obj, sort_keys=True).encode()


def test_official_unreleased_default_remains_no_go():
    result = g.assess_offline(encoded(packet()))
    assert result["offline_manifest_complete"] == "NO"
    assert result["testnet_live_go"] == "NO"
    assert result["inference_post_authorized"] == "NO"
    assert result["faucet_action_authorized"] == "NO"
    assert g.TARGET_CONFIRMED is False


def synthetic_complete():
    p = packet()
    p.update(
        network_state="OPEN", chain_id="fictional-only-001",
        genesis_sha256="a"*64,
        rpc_url="https://api.example.test/rpc",
        faucet_url="https://api.example.test/faucet",
        inference_url="https://api.example.test/inference",
        signed_request_spec_sha256="b"*64,
        settled_receipt_spec_sha256="c"*64,
        rate_rules_sha256="d"*64,
        original_did_continuity_attested=True,
        operator_reviewed_domains=["api.example.test"],
        formal_operator_source_sha256="e"*64,
    )
    return p


def test_even_synthetic_complete_cannot_go_live():
    result = g.assess_offline(encoded(synthetic_complete()))
    assert result["offline_manifest_complete"] == "YES"
    assert result["testnet_live_go"] == "NO"
    assert result["same_original_did_externally_attested"] == "NOT_PROVEN"
    assert result["official_public_release_cryptographically_verified"] == "NO"
    assert result["migration_or_retirement_authorized"] == "NO"


def test_missing_receipt_or_original_did_blocks_completeness():
    for key, value in (("settled_receipt_spec_sha256", None),
                       ("original_did_continuity_attested", False),
                       ("chain_id", None),
                       ("faucet_url", None)):
        p = synthetic_complete()
        p[key] = value
        assert g.assess_offline(encoded(p))["offline_manifest_complete"] == "NO"


def test_non_reviewed_host_rejected_even_if_url_looks_official():
    p = synthetic_complete()
    p["rpc_url"] = "https://unreviewed.example.invalid/rpc"
    with pytest.raises(g.Stop, match="ENDPOINT_NOT_REVIEWED_STOP"):
        g.assess_offline(encoded(p))


@pytest.mark.parametrize("bad", (
    "http://api.example.test/rpc", "https://user@api.example.test/rpc",
    "https://api.example.test:8443/rpc", "https://api.example.test/rpc#skip",
    "https://api.example.test/rpc?token=accidental",
    "https://api.example.test.evil.invalid/rpc",
    "https://api.example.test\\@other.invalid/rpc",
))
def test_unacceptable_network_paths_rejected(bad):
    p = synthetic_complete()
    p["rpc_url"] = bad
    with pytest.raises(g.Stop):
        g.assess_offline(encoded(p))


def test_duplicate_json_keys_rejected():
    p = encoded(packet()).decode()
    duplicate = p.replace('"chain_id": null', '"chain_id": null, "chain_id": null')
    with pytest.raises(g.Stop, match="DUPLICATE_FIELD_STOP"):
        g.private_manifest(duplicate.encode())


def test_manifest_additional_permission_fields_cannot_override_no_go():
    p = packet()
    p["force_live"] = True
    with pytest.raises(g.Stop, match="MANIFEST_EXACT_FIELDS_STOP"):
        g.assess_offline(encoded(p))


def test_private_values_not_exposed_in_report():
    p = synthetic_complete()
    report = g.launch_report(encoded(p))
    assert "api.example.test" not in report
    assert "fictional-only-001" not in report
    assert '"testnet_live_go":"NO"' in report
    assert '"original_oci_signer_ported":"NOT_PROVEN"' in report


def test_no_real_io_calls_are_available_in_source():
    source = SOURCE.read_text(encoding="utf8")
    tree = ast.parse(source)
    no_calls = {"open", "connect", "urlopen", "post", "get", "put", "delete",
                "unlink", "remove", "rmtree", "sign", "write_bytes",
                "write_text", "system", "Popen", "run"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                assert node.func.id not in no_calls
            if isinstance(node.func, ast.Attribute):
                assert node.func.attr not in no_calls
    assert "def main(" not in source
