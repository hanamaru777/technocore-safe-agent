from pathlib import Path

from flop_agent import autopilot


ROOT = Path(__file__).resolve().parents[1]


def test_public_trigger_rules_cannot_make_first_contact_autonomous():
    current = {"candidate_id": "current", "fingerprint": "abcdef1234567890"}
    relationship = {"approval_rejection_history": []}
    state = {"relationships": {current["fingerprint"]: relationship}}

    assert autopilot.sender_trusted_for_autopilot(current, state) is False

    # Approving the candidate that is currently being evaluated cannot turn the
    # same first-contact event into an autonomous write.
    relationship["approval_rejection_history"].append(
        {"candidate_id": "current", "decision": "approved"}
    )
    assert autopilot.sender_trusted_for_autopilot(current, state) is False

    # Only a previous human-approved interaction establishes trust for a later
    # candidate from the same DID/fingerprint.
    relationship["approval_rejection_history"].append(
        {"candidate_id": "earlier", "decision": "approved"}
    )
    assert autopilot.sender_trusted_for_autopilot(current, state) is True


def test_metadata_firewall_is_default_deny_for_non_signer_users():
    script = (ROOT / "packaging/oracle/block-technocore-metadata.sh").read_text("utf-8")

    assert "chain=TECHNOCORE_METADATA" in script
    assert 'iptables -A "$chain" -m owner --uid-owner 0 -j RETURN' in script
    assert 'iptables -A "$chain" -m owner --uid-owner "$signer_uid" -j RETURN' in script
    assert 'iptables -A "$chain" -j REJECT' in script
    assert 'iptables -I OUTPUT 1 -d "$metadata" -j "$chain"' in script


def test_public_security_doc_states_residual_boundaries():
    text = (ROOT / "SECURITY.md").read_text("utf-8")

    assert "Security must not depend on hiding the source code" in text
    assert "first-contact DID is review-only" in text
    assert "root/OS/cloud-control-plane compromise" in text
    assert "finite signed-write replay window" in text
