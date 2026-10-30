"""No network calls: verified baseline and false-positive safeguards."""
import json
import pytest
from flop_agent import airdrop_operator_testnet_watch as op

SECTIONS = """
Chain spec
Unavailable — no verified public value
Expected genesis
Unavailable — no verified public value
Bootnodes
Unavailable — no verified public value
RPC
Unavailable — no verified public value
Gateway
Unavailable — no verified public value
Admission
Unavailable until published network identity
Model catalog
Unavailable — no verified public value
"""


def page(net="planned", release="unreleased", sections=SECTIONS):
    return (f"<html><script>Network: testnet (live) Release: 1 (released)</script>"
            f"<main><h1>testnet network</h1>"
            f"<p>Network: testnet ({net}) · Release: next ({release})</p>"
            f"{sections}</main></html>").encode("utf-8")


def test_official_unreleased_baseline_has_no_candidate():
    status, candidate = op.inspect_public_profile(page())
    assert status == "planned_unreleased"
    assert candidate is None


def test_fake_script_content_cannot_promote_to_network_change():
    assert op.inspect_public_profile(page())[1] is None


@pytest.mark.parametrize("net,release", [
    ("live", "released"), ("open", "unreleased"), ("planned", "released"),
    ("enabled", "active")
])
def test_explicit_status_drift_is_only_a_review(net, release):
    status, candidate = op.inspect_public_profile(page(net,release))
    assert status == "changed_review_only"
    assert candidate["kind"] == "official_operator_profile_review"
    assert candidate["reason"] == "network_or_release_changed_review"
    assert candidate["url"] == op.URL
    assert len(candidate["fingerprint"]) == 64
    assert "faucet" not in str(candidate).lower()
    assert "rpc" not in str(candidate).lower()
    assert "did" not in str(candidate).lower()


def test_when_chain_documentation_changes_while_status_planned_review_only():
    changed = SECTIONS.replace("Chain spec\nUnavailable — no verified public value",
                               "Chain spec\nOfficial chain spec published")
    status, candidate = op.inspect_public_profile(page(sections=changed))
    assert status == "changed_review_only"
    assert candidate["reason"] == "chain_artifacts_changed_review"


@pytest.mark.parametrize("body", [
    b"", b"\xff", b"Testnet is definitely LIVE",
    b"<html><script>Network: testnet (live) Release: v1 (released)</script></html>",
    b"<html>Network: testnet (planned) Release: next (unreleased)</html>",
    b"x"*(op.MAX_BODY+1), "not bytes", None
])
def test_unknown_or_oversized_document_cannot_generate_launch_candidate(body):
    status, candidate = op.inspect_public_profile(body)
    assert status == "unavailable"
    assert candidate is None


@pytest.mark.parametrize("fault", [OSError, ValueError, TimeoutError, TypeError])
def test_unavailable_network_does_not_manufacture_a_launch(fault):
    def fail():
        raise fault("no connection")
    assert op.check(fail) == ("unavailable", None)


def test_injected_network_reader_never_gets_a_wallet_or_did():
    calls = []
    def fake():
        calls.append("PUBLIC_GET_ONLY")
        return page()
    assert op.check(fake) == ("planned_unreleased", None)
    assert calls == ["PUBLIC_GET_ONLY"]


def test_candidate_is_deterministic_and_contains_no_source_body():
    body = page("live", "released") + b"<!-- SECRET_SHOULD_NOT_ESCAPE -->"
    a = op.inspect_public_profile(body)[1]
    b = op.inspect_public_profile(body)[1]
    assert a == b
    assert "SECRET_SHOULD_NOT_ESCAPE" not in json.dumps(a)


def test_existing_launch_watch_keeps_main_radar_and_adds_review_only(monkeypatch):
    from flop_agent import airdrop_launch_watch as launch
    snapshot = {"read_only": True, "health": "ok", "sources": [],
                "resolved_facts": {}, "scanned_at": "2026-10-30T12:00:00Z",
                "snapshot_id": "a" * 64}
    monkeypatch.setattr(launch.airdrop_radar, "scan_official_sources", lambda: snapshot)
    monkeypatch.setattr(launch.operator_watch, "check",
                        lambda: op.inspect_public_profile(page("live", "released")))
    report = launch.run()
    assert report["operator_profile"] == "changed_review_only"
    assert len(report["candidates"]) == 1
    assert report["candidates"][0]["kind"] == "official_operator_profile_review"
    assert report["health"] == "ok"
    assert "action_candidate" not in json.dumps(report)
    assert "transaction" not in json.dumps(report)


def test_operator_site_unavailable_does_not_mark_launch_or_block_existing_radar(monkeypatch):
    from flop_agent import airdrop_launch_watch as launch
    snapshot = {"read_only": True, "health": "ok", "sources": [],
                "resolved_facts": {}, "scanned_at": "2026-10-30T12:00:00Z",
                "snapshot_id": "a" * 64}
    monkeypatch.setattr(launch.airdrop_radar, "scan_official_sources", lambda: snapshot)
    monkeypatch.setattr(launch.operator_watch, "check", lambda: ("unavailable", None))
    report = launch.run()
    assert report["operator_profile"] == "unavailable"
    assert report["candidates"] == []


def test_scheduled_workflow_only_creates_manual_review_issue_from_operator_change():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github/workflows/flop-launch-artifact-watch.yml").read_text("utf-8")
    assert '"official_operator_profile_review"' in workflow
    assert '"official_status_open"' in workflow
    assert "read_only !== true" in workflow
    assert 'state: "all"' in workflow
    assert "github.rest.issues.create" in workflow
    assert "workflow_dispatch:" in workflow
    assert "pull_request:" not in workflow
    assert "secrets." not in workflow
