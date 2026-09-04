from datetime import UTC, datetime

from flop_agent import autopilot, resident

from test_activation_first_contact import cand, setup, write


def test_first_contact_trust_does_not_widen_followup_semantics(monkeypatch, tmp_path):
    rs = setup(monkeypatch, tmp_path)
    fingerprint = "7777777777777777"
    first = cand(
        "first",
        category="help_request",
        fingerprint=fingerprint,
        text="Can you help reproduce this public repo test?",
    )
    write(rs, first)
    assert autopilot.build_outbox()["queued"] == 1

    auto = autopilot.load()
    intent_id = next(iter(auto["first_contact_intents"]))
    item = auto["outbox"][intent_id]
    stamp = datetime.now(UTC).isoformat()
    item.update(
        {
            "status": "acknowledged",
            "posted_at": stamp,
            "acknowledged_at": stamp,
        }
    )
    auto["receipts"][intent_id] = {"at": stamp, "receipt_hash": "c" * 64}
    autopilot.save(auto)

    broad = cand(
        "broad",
        category="help_request",
        fingerprint=fingerprint,
        text="Need test vectors for the DID publish path; happy to help review it.",
    )
    assert autopilot.autopilot_policy._BASE_ELIGIBLE(broad)[0] is False
    assert autopilot.first_contact_eligible(broad)[0] is True

    current = resident.load_state()
    current["candidates"] = {"broad": broad}
    current["relationships"].setdefault(
        fingerprint,
        {
            "approval_rejection_history": [],
            "interaction_history": [],
            "relationship_state": "observed",
        },
    )
    resident.save_state(current)

    assert autopilot.sender_trusted_for_autopilot(
        broad, resident.load_state(), autopilot.load()
    ) is False
    assert autopilot.build_outbox()["queued"] == 0
