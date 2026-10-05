import json
from datetime import UTC, datetime

import pytest

from flop_agent import airdrop_ledger
from flop_agent import precontest_runtime_profile as profile


NOW = datetime(2026, 10, 5, 6, 0, tzinfo=UTC)
CHALLENGE = "profile-test"


def test_missing_profile_is_explicit_noop(tmp_path, monkeypatch):
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)

    assert profile.load(CHALLENGE) is None


def test_save_load_round_trip_is_digest_bound(tmp_path, monkeypatch):
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)

    saved = profile.save(CHALLENGE, "close1_short_liquidity", now=NOW)
    loaded = profile.load(CHALLENGE)

    assert loaded == saved
    assert loaded["challenge_id"] == CHALLENGE
    assert loaded["runtime_profile"] == "close1_short_liquidity"
    assert loaded["configured_at"] == NOW.isoformat()
    assert len(loaded["profile_sha256"]) == 64


def test_tampered_profile_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)
    profile.save(CHALLENGE, "close1_short_liquidity", now=NOW)
    path = profile.profile_path(CHALLENGE)
    value = json.loads(path.read_text("utf-8"))
    value["runtime_profile"] = "other"
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(
        profile.RuntimeProfileError,
        match="precontest_runtime_profile_integrity_invalid",
    ):
        profile.load(CHALLENGE)


def test_unsupported_profile_is_rejected_before_write(tmp_path, monkeypatch):
    monkeypatch.setattr(airdrop_ledger, "ledger_dir", lambda: tmp_path)

    with pytest.raises(ValueError, match="precontest_runtime_profile_invalid"):
        profile.save(CHALLENGE, "unknown_profile", now=NOW)

    assert profile.load(CHALLENGE) is None
