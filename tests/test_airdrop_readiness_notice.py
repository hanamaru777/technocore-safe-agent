from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from flop_agent import airdrop_monitor, airdrop_notifier, core


T0 = datetime(2026, 9, 19, 0, 0, tzinfo=UTC)


@pytest.fixture
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(core, "STATE", tmp_path)
    monkeypatch.setattr(airdrop_notifier, "_pending_by_route", lambda: ([], []))
    return tmp_path


def readiness(
    *,
    faucet_state: str = "BLOCKED",
    faucet_blockers: list[str] | None = None,
    registration_state: str = "BLOCKED",
    registration_blockers: list[str] | None = None,
    claim_state: str = "BLOCKED",
    claim_blockers: list[str] | None = None,
    ledger_valid: bool = True,
) -> dict:
    return {
        "overall": (
            "IMPLEMENTATION_READY"
            if all(
                state == "IMPLEMENTATION_READY"
                for state in (faucet_state, registration_state, claim_state)
            )
            else "BLOCKED"
        ),
        "snapshot_id": "s" * 64,
        "ledger_valid": ledger_valid,
        "actions": {
            "faucet": {
                "state": faucet_state,
                "blockers": faucet_blockers
                if faucet_blockers is not None
                else ["not_open:testnet_status:planned", "canonical_open_event_missing"],
            },
            "registration": {
                "state": registration_state,
                "blockers": registration_blockers
                if registration_blockers is not None
                else ["missing_fact:registration_status", "canonical_open_event_missing"],
            },
            "claim": {
                "state": claim_state,
                "blockers": claim_blockers
                if claim_blockers is not None
                else ["claim_path_unresolved", "e38_unresolved"],
            },
        },
    }


def monitor_status(report: dict) -> dict:
    return {
        "outcome": "recorded",
        "last_attempt_at": T0.isoformat(),
        "last_completed_at": T0.isoformat(),
        "heartbeat_age_seconds": 0,
        "heartbeat_stale": False,
        "radar_health": "ok",
        "staging_outcome": "ok",
        "staging_error_type": None,
        "adapter_readiness": report,
    }


def install_status(
    monkeypatch: pytest.MonkeyPatch,
    holder: dict,
) -> None:
    monkeypatch.setattr(
        airdrop_monitor,
        "monitor_status",
        lambda now=None: monitor_status(holder["report"]),
    )


def read_state() -> dict:
    return json.loads(airdrop_notifier.state_path().read_text("utf-8"))


def test_old_notifier_state_loads_with_readiness_fields(
    isolated_state: Path,
) -> None:
    path = airdrop_notifier.state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "last_run_at": T0.isoformat(),
                "last_success_at": T0.isoformat(),
                "failure_count": 0,
                "next_attempt_at": None,
                "last_error_type": None,
                "digest_due_at": None,
                "health_notice_state": "healthy",
                "health_notice_at": None,
            }
        ),
        encoding="utf-8",
    )

    state = airdrop_notifier._load_state()
    assert state["readiness_notice_fingerprint"] is None
    assert state["readiness_notice_snapshot"] is None
    assert state["readiness_notice_at"] is None


def test_first_valid_readiness_establishes_silent_baseline(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    holder = {"report": readiness()}
    install_status(monkeypatch, holder)
    sent: list[str] = []

    result = airdrop_notifier.run_once(
        sender=lambda message: sent.append(message) or "100",
        now=T0,
    )

    assert result["outcome"] == "ok"
    assert result["sent"] == 0
    assert sent == []
    state = read_state()
    assert isinstance(state["readiness_notice_fingerprint"], str)
    assert state["readiness_notice_snapshot"]["actions"]["faucet"]["state"] == "BLOCKED"

    second = airdrop_notifier.run_once(
        sender=lambda message: sent.append(message) or "101",
        now=T0 + timedelta(minutes=1),
    )
    assert second["sent"] == 0
    assert sent == []


def test_blocker_change_notifies_once_after_success(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    holder = {"report": readiness()}
    install_status(monkeypatch, holder)
    sent: list[str] = []

    airdrop_notifier.run_once(
        sender=lambda message: sent.append(message) or "100",
        now=T0,
    )
    old = read_state()["readiness_notice_fingerprint"]

    holder["report"] = readiness(
        faucet_blockers=["canonical_open_event_missing"],
    )
    changed = airdrop_notifier.run_once(
        sender=lambda message: sent.append(message) or "101",
        now=T0 + timedelta(minutes=1),
    )

    assert changed["sent"] == 1
    assert len(sent) == 1
    assert "Adapter Readiness 更新" in sent[0]
    assert "faucet" in sent[0]
    assert "解消:" in sent[0]
    assert "not_open:testnet_status:planned" in sent[0]
    assert read_state()["readiness_notice_fingerprint"] != old

    unchanged = airdrop_notifier.run_once(
        sender=lambda message: sent.append(message) or "102",
        now=T0 + timedelta(minutes=2),
    )
    assert unchanged["sent"] == 0
    assert len(sent) == 1


def test_ready_transition_is_high_signal_but_not_execution_authorization(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    holder = {"report": readiness()}
    install_status(monkeypatch, holder)
    sent: list[str] = []

    airdrop_notifier.run_once(
        sender=lambda message: sent.append(message) or "100",
        now=T0,
    )

    holder["report"] = readiness(
        faucet_state="IMPLEMENTATION_READY",
        faucet_blockers=[],
    )
    result = airdrop_notifier.run_once(
        sender=lambda message: sent.append(message) or "101",
        now=T0 + timedelta(minutes=1),
    )

    assert result["sent"] == 1
    assert "🔴 FLOP Adapter Readiness: IMPLEMENTATION_READY" in sent[0]
    assert "faucet: BLOCKED → IMPLEMENTATION_READY" in sent[0]
    assert "IMPLEMENTATION_READYは実行許可ではありません" in sent[0]
    assert "実adapter実装・登録・外部writeは別の監査と承認が必要" in sent[0]


def test_failed_readiness_send_does_not_advance_dedupe_state(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    holder = {"report": readiness()}
    install_status(monkeypatch, holder)

    airdrop_notifier.run_once(sender=lambda _message: "100", now=T0)
    before = read_state()["readiness_notice_fingerprint"]

    holder["report"] = readiness(
        registration_blockers=["canonical_open_event_missing"],
    )

    def fail(_message: str) -> str:
        raise airdrop_notifier.NotifierSendError(
            "simulated_send_failure",
            status_code=503,
        )

    failed = airdrop_notifier.run_once(
        sender=fail,
        now=T0 + timedelta(minutes=1),
    )
    assert failed["outcome"] == "send_failed"
    assert read_state()["readiness_notice_fingerprint"] == before

    sent: list[str] = []
    retry = airdrop_notifier.run_once(
        sender=lambda message: sent.append(message) or "101",
        now=T0 + timedelta(minutes=3),
    )
    assert retry["outcome"] == "ok"
    assert retry["sent"] == 1
    assert len(sent) == 1
    assert read_state()["readiness_notice_fingerprint"] != before


def test_invalid_readiness_does_not_reset_last_good_baseline(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    holder = {"report": readiness()}
    install_status(monkeypatch, holder)

    airdrop_notifier.run_once(sender=lambda _message: "100", now=T0)
    before = read_state()

    holder["report"] = readiness(ledger_valid=False)
    sent: list[str] = []
    result = airdrop_notifier.run_once(
        sender=lambda message: sent.append(message) or "101",
        now=T0 + timedelta(minutes=1),
    )

    after = read_state()
    assert result["sent"] == 0
    assert sent == []
    assert after["readiness_notice_fingerprint"] == before["readiness_notice_fingerprint"]
    assert after["readiness_notice_snapshot"] == before["readiness_notice_snapshot"]


def test_tampered_readiness_state_fails_closed(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    holder = {"report": readiness()}
    install_status(monkeypatch, holder)

    airdrop_notifier.run_once(sender=lambda _message: "100", now=T0)
    state = read_state()
    state["readiness_notice_snapshot"]["actions"]["faucet"]["blockers"] = [
        "tampered"
    ]
    airdrop_notifier.state_path().write_text(
        json.dumps(state),
        encoding="utf-8",
    )

    result = airdrop_notifier.run_once(
        sender=lambda _message: "101",
        now=T0 + timedelta(minutes=1),
    )
    assert result["outcome"] == "send_failed"
    assert result["error_type"] == "RuntimeError"


def test_readiness_notice_render_is_bounded_and_neutralizes_mentions() -> None:
    previous = airdrop_notifier._normalize_readiness(
        monitor_status(readiness())
    )
    current = airdrop_notifier._normalize_readiness(
        monitor_status(
            readiness(
                faucet_blockers=[
                    "@everyone:" + ("x" * 230),
                    "canonical_open_event_missing",
                ]
            )
        )
    )
    assert previous is not None
    assert current is not None

    rendered = airdrop_notifier._render_readiness_change(previous, current)
    assert len(rendered) <= airdrop_notifier.MAX_CONTENT
    assert "@everyone" not in rendered
    assert "＠everyone" in rendered


def test_notifier_status_exposes_only_readiness_notice_metadata(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    holder = {"report": readiness()}
    install_status(monkeypatch, holder)
    airdrop_notifier.run_once(sender=lambda _message: "100", now=T0)

    status = airdrop_notifier.status(now=T0 + timedelta(minutes=1))
    assert status["readiness_notice_initialized"] is True
    assert status["readiness_notice_at"] == T0.isoformat()
    rendered = json.dumps(status).lower()
    assert "blockers" not in rendered
    assert "fingerprint" not in rendered
    assert "token" not in rendered
