from __future__ import annotations

import inspect
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from flop_agent import airdrop_monitor, airdrop_notifier, airdrop_radar, core


T0 = datetime(2026, 9, 19, 0, 0, tzinfo=UTC)


@pytest.fixture
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(core, "STATE", tmp_path)
    return tmp_path


def _alert(
    event_id: str,
    *,
    route: str = "immediate",
    severity: str = "HIGH",
    key: str = "genesis_agent_airdrop",
    before: object = 1,
    after: object = 2,
) -> dict:
    return {
        "event_id": event_id,
        "first_queued_at": T0.isoformat(),
        "last_seen": T0.isoformat(),
        "route": route,
        "delivery_state": "pending",
        "payload": {
            "event_id": event_id,
            "severity": severity,
            "type": "CHANGED",
            "key": key,
            "route": route,
            "source": "yellowpaper",
            "source_url": "https://flop.finance/intro/yellowpaper/",
            "authority": "normative",
            "tier": 1,
            "source_version": "0.5.0",
            "before": before,
            "after": after,
            "deadline": None,
            "deadline_gate": None,
            "safe_next_step": (
                "Review the official evidence and before→after change; "
                "do not take binding action without approval."
            ),
        },
    }


def _write_alerts(base: Path, *rows: dict) -> None:
    directory = base / "airdrop-radar"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "alert-outbox.json").write_text(
        json.dumps(
            {
                "schema_version": airdrop_monitor.SCHEMA_VERSION,
                "updated_at": T0.isoformat(),
                "events": {row["event_id"]: row for row in rows},
            }
        ),
        "utf-8",
    )


def _valid_snapshot(snapshot_id: str, at: datetime) -> dict:
    return {
        "schema_version": airdrop_radar.SCHEMA_VERSION,
        "read_only": True,
        "scanned_at": at.isoformat(),
        "health": "ok",
        "snapshot_id": snapshot_id,
        "source_precedence": [],
        "sources": [],
        "resolved_facts": {},
        "deadlines": [],
        "summary": {
            "available_sources": 0,
            "failed_sources": [],
            "conflicts": [],
        },
        "warnings": [],
    }


def test_immediate_success_marks_delivered_only_after_send(
    isolated_state: Path,
) -> None:
    _write_alerts(isolated_state, _alert("event-1"))
    sent: list[str] = []

    def sender(content: str) -> str:
        assert airdrop_monitor.alert_delivery_status("event-1")["delivery_state"] == "pending"
        sent.append(content)
        return "123456789"

    result = airdrop_notifier.run_once(sender=sender, now=T0)
    assert result["outcome"] == "ok"
    assert result["sent"] == 1
    assert len(sent) == 1
    status = airdrop_monitor.alert_delivery_status("event-1")
    assert status["delivery_state"] == "delivered"
    assert status["delivery_transport"] == "discord"
    assert status["delivery_receipt"] == "123456789"


def test_send_failure_leaves_alert_pending_and_backoff_visible(
    isolated_state: Path,
) -> None:
    _write_alerts(isolated_state, _alert("event-fail"))

    def sender(_content: str) -> str:
        raise airdrop_notifier.NotifierSendError(
            "rate_limited",
            status_code=429,
            retry_after_seconds=180,
        )

    result = airdrop_notifier.run_once(sender=sender, now=T0)
    assert result["outcome"] == "send_failed"
    assert result["sent"] == 0
    assert result["retry_in_seconds"] >= 180
    assert airdrop_monitor.alert_delivery_status("event-fail")["delivery_state"] == "pending"

    called = 0

    def must_not_send(_content: str) -> str:
        nonlocal called
        called += 1
        return "123"

    blocked = airdrop_notifier.run_once(
        sender=must_not_send,
        now=T0 + timedelta(seconds=60),
    )
    assert blocked["outcome"] == "backoff"
    assert called == 0


def test_immediate_batch_is_bounded_to_six_per_run(
    isolated_state: Path,
) -> None:
    rows = [_alert(f"event-{i}") for i in range(8)]
    _write_alerts(isolated_state, *rows)
    sent: list[str] = []

    def sender(content: str) -> str:
        sent.append(content)
        return str(100000 + len(sent))

    first = airdrop_notifier.run_once(sender=sender, now=T0)
    assert first["sent"] == airdrop_notifier.MAX_IMMEDIATE_PER_RUN
    assert first["pending_immediate"] == 2
    assert len(sent) == 6

    second = airdrop_notifier.run_once(
        sender=sender,
        now=T0 + timedelta(minutes=1),
    )
    assert second["pending_immediate"] == 0
    assert len(sent) == 8


def test_medium_alerts_wait_then_bundle_and_mark_atomically(
    isolated_state: Path,
) -> None:
    _write_alerts(
        isolated_state,
        _alert("medium-a", route="digest", severity="MEDIUM", key="github_interest_repo_names"),
        _alert("medium-b", route="digest", severity="MEDIUM", key="official_signal"),
    )
    sent: list[str] = []

    def sender(content: str) -> str:
        sent.append(content)
        return "777777"

    early = airdrop_notifier.run_once(sender=sender, now=T0)
    assert early["sent"] == 0
    assert early["pending_digest"] == 2
    state = json.loads(airdrop_notifier.state_path().read_text("utf-8"))
    assert state["digest_due_at"] == (
        T0 + timedelta(seconds=airdrop_notifier.DIGEST_INTERVAL_SECONDS)
    ).isoformat()

    due = airdrop_notifier.run_once(
        sender=sender,
        now=T0 + timedelta(seconds=airdrop_notifier.DIGEST_INTERVAL_SECONDS),
    )
    assert due["sent"] == 1
    assert due["pending_digest"] == 0
    assert len(sent) == 1
    assert "medium-a" in sent[0]
    assert "medium-b" in sent[0]
    assert airdrop_monitor.alert_delivery_status("medium-a")["delivery_receipt"] == "777777"
    assert airdrop_monitor.alert_delivery_status("medium-b")["delivery_receipt"] == "777777"


def test_health_problem_is_deduped_and_recovery_notified(
    isolated_state: Path,
) -> None:
    def failing_scan() -> dict:
        raise TimeoutError("simulated source timeout")

    airdrop_monitor.run_once(scanner=failing_scan, now=T0)
    sent: list[str] = []

    def sender(content: str) -> str:
        sent.append(content)
        return str(900000 + len(sent))

    first = airdrop_notifier.run_once(
        sender=sender,
        now=T0 + timedelta(minutes=1),
    )
    assert first["sent"] == 1
    assert "監視異常" in sent[-1]

    second = airdrop_notifier.run_once(
        sender=sender,
        now=T0 + timedelta(minutes=2),
    )
    assert second["sent"] == 0

    recovered_at = T0 + timedelta(minutes=15)
    airdrop_monitor.run_once(
        scanner=lambda: _valid_snapshot("recovered", recovered_at),
        now=recovered_at,
    )
    recovered = airdrop_notifier.run_once(
        sender=sender,
        now=recovered_at + timedelta(minutes=1),
    )
    assert recovered["sent"] == 1
    assert "監視復旧" in sent[-1]


def test_never_run_baseline_does_not_emit_false_health_alarm(
    isolated_state: Path,
) -> None:
    sent: list[str] = []
    result = airdrop_notifier.run_once(
        sender=lambda content: sent.append(content) or "123",
        now=T0,
    )
    assert result["outcome"] == "ok"
    assert result["sent"] == 0
    assert result["health"] == "unknown"
    assert sent == []


def test_rendered_alert_neutralizes_mentions_and_is_bounded() -> None:
    payload = _alert(
        "mention-event",
        key="@everyone " + ("x" * 4000),
        before="@here",
        after="<@123456789>",
    )["payload"]
    rendered = airdrop_notifier.render_alert(payload)
    assert len(rendered) <= airdrop_notifier.MAX_CONTENT
    assert "@everyone" not in rendered
    assert "@here" not in rendered
    assert "<@123456789>" not in rendered
    assert "＠everyone" in rendered


class _FakeDiscordResponse:
    status_code = 201

    def json(self):
        return {"id": "987654321"}


class _FakeDiscordClient:
    def __init__(self, capture: dict, **kwargs) -> None:
        capture["client_kwargs"] = kwargs
        self.capture = capture

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def post(self, url: str, *, json: dict):
        self.capture["url"] = url
        self.capture["json"] = json
        return _FakeDiscordResponse()


def test_default_discord_sender_disables_mentions_and_never_persists_token(
    isolated_state: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "super-secret-discord-token-value"
    monkeypatch.setenv("DISCORD_BOT_TOKEN", secret)
    monkeypatch.setenv("DISCORD_CHANNEL_ID", "123456")
    capture: dict = {}

    monkeypatch.setattr(
        airdrop_notifier.httpx,
        "Client",
        lambda **kwargs: _FakeDiscordClient(capture, **kwargs),
    )
    sender = airdrop_notifier._discord_sender_from_env()
    assert sender("hello @everyone") == "987654321"

    assert capture["url"] == "https://discord.com/api/v10/channels/123456/messages"
    assert capture["json"]["allowed_mentions"] == {"parse": []}
    assert capture["json"]["flags"] == 4
    assert capture["client_kwargs"]["follow_redirects"] is False
    assert capture["client_kwargs"]["headers"]["Authorization"] == f"Bot {secret}"

    # Saving notifier state must never serialize the token.
    airdrop_notifier.run_once(sender=lambda _content: "111", now=T0)
    for path in (isolated_state / "airdrop-radar").glob("*"):
        if path.is_file():
            assert secret not in path.read_text("utf-8", errors="ignore")


def test_notifier_status_contains_no_credentials(
    isolated_state: Path,
) -> None:
    status = airdrop_notifier.status(now=T0)
    assert "token" not in json.dumps(status).lower()
    assert status["pending_immediate"] == 0
    assert status["pending_digest"] == 0


def test_notifier_module_has_only_discord_external_write_path() -> None:
    source = inspect.getsource(airdrop_notifier).lower()
    assert "https://discord.com/api/v10" in source
    assert "technocore.chat" not in source
    assert "flop.finance" not in source
    assert "x.com" not in source
    assert "sign_seed" not in source
    assert "subprocess" not in source
    assert ".post(endpoint" in source
    assert ".put(" not in source
    assert ".delete(" not in source
