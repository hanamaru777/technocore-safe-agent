import json
from datetime import UTC, datetime, timedelta

import pytest

from flop_agent import (
    airdrop_ledger,
    discord_mission_compact,
    precontest_candidate_discovery as candidates,
    precontest_supervisor as supervisor,
)


NOW = datetime(2026, 10, 6, 3, 40, tzinfo=UTC)
GITHUB_URL = "https://api.github.com/orgs/flop-labs/repos?per_page=100&sort=pushed"


def _activity(*rows):
    return {
        "value": list(rows),
        "source": "github_org",
        "tier": 3,
        "authority": "engineering",
        "status": "engineering",
        "conflict": False,
        "variants": [],
    }


def _repo(name, *, archived=False, pushed="2026-10-06T03:00:00+00:00"):
    return {
        "name": name,
        "archived": archived,
        "default_branch": "main",
        "pushed_at": pushed,
    }


def _record(seq, event_id, before, after, *, event_type="CHANGED"):
    observed = (NOW + timedelta(seconds=seq)).isoformat()
    return {
        "schema_version": 1,
        "sequence": seq,
        "record_type": "material_event",
        "event_id": event_id,
        "first_seen": observed,
        "last_seen": observed,
        "observed_at": observed,
        "previous_hash": "",
        "hash": "f" * 64,
        "event": {
            "event_id": event_id,
            "type": event_type,
            "key": "github_critical_repo_activity",
            "severity": "MEDIUM",
            "before": before,
            "after": after,
        },
        "source_evidence": [
            {
                "observation": "current",
                "name": "github_org",
                "url": GITHUB_URL,
                "tier": 3,
                "authority": "engineering",
                "status": "ok",
            }
        ],
    }


def _verified(records):
    return {"valid": True, "count": len(records), "tip_hash": "a" * 64 if records else "", "records": records}


def _spec(challenge_id, repo_name):
    deadline = NOW + timedelta(days=2)
    return {
        "schema_version": 1,
        "challenge_id": challenge_id,
        "opening": None,
        "deadline": deadline.isoformat(),
        "prize": None,
        "eligibility": {},
        "submission": {},
        "collaboration_required": False,
        "registration_required": False,
        "source": {
            "rules_url": f"https://raw.githubusercontent.com/flop-labs/{repo_name}/{'1' * 40}/README.md",
            "authority_type": "flop_labs_github",
            "authority_id": f"flop-labs/{repo_name}",
            "pinned_commit": "1" * 40,
            "source_sha256": None,
        },
        "required_artifacts": [],
        "notes": [],
    }


def _setup(tmp_path, monkeypatch, records):
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)
    monkeypatch.setattr(airdrop_ledger, "verify_ledger", lambda: _verified(records))


def test_new_challenge_repo_only_is_candidate_not_existing_baseline_repo(tmp_path, monkeypatch):
    existing = _repo("technocore-close-call-challenge")
    new = _repo("next-alpha-challenge")
    nonchallenge = _repo("flop-core")
    archived = _repo("old-archived-challenge", archived=True)
    records = [
        _record(
            1,
            "1" * 24,
            _activity(existing),
            _activity(existing, new, nonchallenge, archived),
        )
    ]
    _setup(tmp_path, monkeypatch, records)

    state = candidates.refresh_from_ledger(now=NOW)

    assert list(state["candidates"]) == ["next-alpha-challenge"]
    row = state["candidates"]["next-alpha-challenge"]
    assert row["listed_now"] is True
    assert row["event_ids"] == ["1" * 24]


def test_removed_candidate_stops_blocking_but_evidence_is_retained(tmp_path, monkeypatch):
    repo = _repo("next-alpha-challenge")
    records = [
        _record(1, "1" * 24, _activity(), _activity(repo)),
        _record(2, "2" * 24, _activity(repo), _activity()),
    ]
    _setup(tmp_path, monkeypatch, records)

    state = candidates.refresh_from_ledger(now=NOW)

    row = state["candidates"]["next-alpha-challenge"]
    assert row["listed_now"] is False
    assert row["event_ids"] == ["1" * 24, "2" * 24]
    assert candidates.unregistered_candidates(state) == []


def test_registered_official_repo_no_longer_blocks(tmp_path, monkeypatch):
    repo = _repo("next-alpha-challenge")
    records = [_record(1, "1" * 24, _activity(), _activity(repo))]
    _setup(tmp_path, monkeypatch, records)
    directory = tmp_path / "challenges" / "next-alpha"
    directory.mkdir(parents=True)
    (directory / "spec.json").write_text(
        json.dumps(_spec("next-alpha", "next-alpha-challenge")),
        encoding="utf-8",
    )

    state = candidates.refresh_from_ledger(now=NOW)

    assert candidates.unregistered_candidates(state) == []
    assert state["candidates"]["next-alpha-challenge"]["listed_now"] is True


def test_tampered_candidate_state_fails_closed_instead_of_self_healing(tmp_path, monkeypatch):
    repo = _repo("next-alpha-challenge")
    records = [_record(1, "1" * 24, _activity(), _activity(repo))]
    _setup(tmp_path, monkeypatch, records)
    candidates.refresh_from_ledger(now=NOW)
    path = candidates.state_path()
    value = json.loads(path.read_text("utf-8"))
    value["candidates"]["next-alpha-challenge"]["listed_now"] = False
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(candidates.CandidateDiscoveryError, match="state_integrity_invalid"):
        candidates.refresh_from_ledger(now=NOW)


def test_supervisor_prep_required_with_zero_specs_and_one_unregistered_candidate(tmp_path, monkeypatch):
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)
    fake_state = candidates._empty()
    row = {
        "repo_name": "next-alpha-challenge",
        "first_seen_at": NOW.isoformat(),
        "last_seen_at": NOW.isoformat(),
        "listed_now": True,
        "default_branch": "main",
        "pushed_at": NOW.isoformat(),
        "event_ids": ["1" * 24],
    }
    monkeypatch.setattr(
        supervisor.precontest_candidate_discovery,
        "refresh_from_ledger",
        lambda now=None: fake_state,
    )
    monkeypatch.setattr(
        supervisor.precontest_candidate_discovery,
        "unregistered_candidates",
        lambda state=None: [{**row, "registered": False}],
    )

    result = supervisor.build_status(now=NOW)

    assert result["challenge_count"] == 0
    assert result["status"] == "PREP_REQUIRED"
    assert result["candidate_discovery_status"] == "ok"
    assert result["unregistered_candidate_count"] == 1
    assert result["unregistered_candidates"][0]["repo_name"] == "next-alpha-challenge"


def test_supervisor_candidate_discovery_failure_is_action_required_not_silent(tmp_path, monkeypatch):
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)

    def fail(*_args, **_kwargs):
        raise candidates.CandidateDiscoveryError("precontest_candidate_state_integrity_invalid")

    monkeypatch.setattr(supervisor.precontest_candidate_discovery, "refresh_from_ledger", fail)

    result = supervisor.build_status(now=NOW)

    assert result["status"] == "ACTION_REQUIRED"
    assert result["candidate_discovery_status"] == "error"
    assert result["candidate_discovery_error"] == "precontest_candidate_state_integrity_invalid"


def test_mission_control_names_unregistered_candidate_blocker(tmp_path, monkeypatch):
    path = tmp_path / "precontest-supervisor.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": supervisor.SCHEMA_VERSION,
                "status": "PREP_REQUIRED",
                "candidate_discovery_status": "ok",
                "unregistered_candidate_count": 1,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(supervisor, "state_path", lambda: path)

    assert (
        discord_mission_compact._precontest_blocker()
        == "新しい公式challenge候補のルール固定・spec登録が未完了"
    )
