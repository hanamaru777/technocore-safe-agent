import json
from datetime import UTC, datetime

import pytest

from flop_agent import (
    airdrop_ledger,
    precontest_candidate_discovery as discovery,
    precontest_candidate_review as review,
    precontest_supervisor as supervisor,
)


NOW = datetime(2026, 10, 6, 4, 10, tzinfo=UTC)
REPO = "next-alpha-challenge"


def _candidate():
    return {
        "repo_name": REPO,
        "first_seen_at": "2026-10-06T04:00:00+00:00",
        "last_seen_at": "2026-10-06T04:05:00+00:00",
        "listed_now": True,
        "default_branch": "main",
        "pushed_at": "2026-10-06T03:59:00+00:00",
        "event_ids": ["1" * 24],
    }


def _candidate_state(candidate=None):
    row = candidate or _candidate()
    value = {
        "schema_version": discovery.SCHEMA_VERSION,
        "non_binding": True,
        "updated_at": NOW.isoformat(),
        "ledger_count": 1,
        "ledger_tip_hash": "a" * 64,
        "candidates": {REPO: row},
    }
    value["state_sha256"] = discovery._digest(value)
    return value


def test_packet_contains_identity_and_only_unknown_rule_values():
    packet = review.build_packet(_candidate(), now=NOW)

    assert packet["status"] == "RULES_REVIEW_REQUIRED"
    assert packet["non_binding"] is True
    assert packet["repo_name"] == REPO
    assert packet["official_repo_url"] == f"https://github.com/flop-labs/{REPO}"
    assert packet["official_api_url"] == f"https://api.github.com/repos/flop-labs/{REPO}"
    assert packet["default_branch"] == "main"
    assert set(packet["unknown_rules"]) == set(review.REQUIRED_UNKNOWN_FIELDS)
    assert all(
        row == {"status": "UNKNOWN", "value": None}
        for row in packet["unknown_rules"].values()
    )
    assert packet["packet_sha256"] == review._digest(
        {key: value for key, value in packet.items() if key != "packet_sha256"}
    )


def test_save_then_reload_validates_even_when_json_keys_are_sorted(tmp_path, monkeypatch):
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)

    saved = review.save_packet(_candidate(), now=NOW)
    reloaded = review._load_existing(REPO)

    assert reloaded is not None
    assert reloaded["packet_sha256"] == saved["packet_sha256"]
    assert review.validate_packet(reloaded, expected_repo=REPO)["repo_name"] == REPO


def test_packet_rejects_fabricated_rule_even_with_resealed_digest():
    packet = review.build_packet(_candidate(), now=NOW)
    packet["unknown_rules"]["deadline"] = {
        "status": "KNOWN",
        "value": "2026-10-07T00:00:00+00:00",
    }
    packet["packet_sha256"] = review._digest(
        {key: value for key, value in packet.items() if key != "packet_sha256"}
    )

    with pytest.raises(review.CandidateReviewError, match="rule_fabricated"):
        review.validate_packet(packet, expected_repo=REPO)


def test_tampered_existing_packet_fails_closed_before_refresh(tmp_path, monkeypatch):
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)
    review.save_packet(_candidate(), now=NOW)
    path = review.packet_path(REPO)
    value = json.loads(path.read_text("utf-8"))
    value["default_branch"] = "evil"
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(review.CandidateReviewError, match="integrity_invalid"):
        review.save_packet(_candidate(), now=NOW)


def test_ensure_for_unregistered_skips_registered_candidate(tmp_path, monkeypatch):
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)
    state = _candidate_state()
    monkeypatch.setattr(discovery, "registered_repo_names", lambda: {REPO})

    assert review.ensure_for_unregistered(state, now=NOW) == []
    assert not review.packet_path(REPO).exists()


def test_supervisor_generates_review_packet_for_unregistered_candidate(tmp_path, monkeypatch):
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)
    state = _candidate_state()
    monkeypatch.setattr(
        supervisor.precontest_candidate_discovery,
        "refresh_from_ledger",
        lambda now=None: state,
    )
    monkeypatch.setattr(discovery, "registered_repo_names", lambda: set())

    result = supervisor.build_status(now=NOW)

    assert result["status"] == "PREP_REQUIRED"
    assert result["unregistered_candidate_count"] == 1
    row = result["unregistered_candidates"][0]
    assert row["repo_name"] == REPO
    assert row["review_status"] == "RULES_REVIEW_REQUIRED"
    assert len(row["review_packet_sha256"]) == 64
    packet = review._load_existing(REPO)
    assert packet is not None
    assert all(item["value"] is None for item in packet["unknown_rules"].values())


def test_supervisor_tampered_review_packet_is_action_required(tmp_path, monkeypatch):
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)
    state = _candidate_state()
    monkeypatch.setattr(
        supervisor.precontest_candidate_discovery,
        "refresh_from_ledger",
        lambda now=None: state,
    )
    monkeypatch.setattr(discovery, "registered_repo_names", lambda: set())
    review.save_packet(_candidate(), now=NOW)
    path = review.packet_path(REPO)
    value = json.loads(path.read_text("utf-8"))
    value["warning"] = "tampered"
    path.write_text(json.dumps(value), encoding="utf-8")

    result = supervisor.build_status(now=NOW)

    assert result["status"] == "ACTION_REQUIRED"
    assert result["candidate_discovery_status"] == "error"
    assert result["candidate_discovery_error"] == "precontest_review_integrity_invalid"
