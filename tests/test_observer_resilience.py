import asyncio
import json

from flop_agent import core, observer, observer_resilience


def setup(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    config = {**observer.DEFAULT_CONFIG, "read_budget_per_minute": 600}
    observer.atomic_json_write(observer.config_path(), config)
    return config


def message(seq, text="hello", did="did:key:z6MkAgent"):
    return {
        "seq": seq,
        "from": did,
        "text": text,
        "ts": "2026-09-04T00:00:00Z",
    }


def export_body(start, end):
    return "\n".join(json.dumps(message(seq)) for seq in range(start, end + 1)) + "\n"


def export_body_ranges(*ranges):
    rows = []
    for start, end in ranges:
        rows.extend(json.dumps(message(seq)) for seq in range(start, end + 1))
    return "\n".join(rows) + "\n"


class ExportResponse:
    def __init__(self, body="", status=200, headers=None):
        self.content = body.encode("utf-8")
        self.status_code = status
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise observer.httpx.HTTPStatusError(
                "bad",
                request=None,
                response=self,
            )


class ExportClient:
    def __init__(self, body="", status=200, headers=None):
        self.body = body
        self.status = status
        self.headers = headers or {}
        self.calls = []

    async def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        assert url.endswith("/export")
        return ExportResponse(self.body, self.status, self.headers)


def run_recovery(
    client,
    state,
    config,
    live,
    *,
    bootstrap=False,
):
    return asyncio.run(
        observer_resilience.process_live_payload_with_recovery(
            client,
            observer.ReadBudget(600),
            state,
            config,
            "lobby",
            {"messages": live},
            None,
            None,
            bootstrap=bootstrap,
        )
    )


def test_recoverable_hot_room_gap_is_drained_before_live_slice(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()
    state["cursors"]["lobby"] = 100
    client = ExportClient(export_body(101, 500))

    changed, drain = run_recovery(
        client,
        state,
        config,
        [message(seq) for seq in range(301, 501)],
    )

    assert changed is True
    assert drain is True
    assert state["cursors"]["lobby"] == 500
    assert state["metrics"]["gap_recovery_attempts"] == 1
    assert state["metrics"]["gap_recovery_batches"] == 1
    assert state["metrics"]["gap_recovered_messages"] == 200
    assert state["metrics"]["message_gaps"] == 0
    assert state["metrics"]["estimated_missing_messages"] == 0
    assert state["metrics"]["unrecoverable_gap_events"] == 0
    assert len(client.calls) == 1


def test_single_export_snapshot_drains_all_bounded_chunks_before_live_slice(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()
    state["cursors"]["lobby"] = 100
    client = ExportClient(export_body(101, 500))
    monkeypatch.setattr(observer_resilience, "RECOVERY_CHUNK_MESSAGES", 50)

    changed, drain = run_recovery(
        client,
        state,
        config,
        [message(seq) for seq in range(301, 501)],
    )

    assert changed is True
    assert drain is True
    assert state["cursors"]["lobby"] == 500
    assert state["metrics"]["gap_recovered_messages"] == 200
    assert state["metrics"]["gap_recovery_batches"] == 4
    assert state["metrics"]["message_gaps"] == 0
    assert len(client.calls) == 1
    assert max(
        ref["seq"]
        for agent in state["agents"].values()
        for ref in agent["facts"]["message_refs"]
    ) == 500


def test_production_sized_gap_uses_one_export_for_multiple_2000_message_chunks(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path)
    config["memory_retention"] = 8
    state = observer_resilience.default_state()
    state["cursors"]["lobby"] = 1000
    client = ExportClient(export_body(1001, 9000))

    changed, drain = run_recovery(
        client,
        state,
        config,
        [message(seq) for seq in range(8801, 9001)],
    )

    assert changed is True
    assert drain is True
    assert state["cursors"]["lobby"] == 9000
    assert state["metrics"]["gap_recovery_attempts"] == 1
    assert state["metrics"]["gap_recovery_batches"] == 4
    assert state["metrics"]["gap_recovered_messages"] == 7800
    assert state["metrics"]["message_gaps"] == 0
    assert state["metrics"]["unrecoverable_gap_events"] == 0
    assert len(client.calls) == 1


def test_unrecoverable_ring_loss_is_explicit_then_retained_tail_is_recovered(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()
    state["cursors"]["lobby"] = 100
    client = ExportClient(export_body(200, 500))

    changed, _ = run_recovery(
        client,
        state,
        config,
        [message(seq) for seq in range(301, 501)],
    )

    assert changed is True
    assert state["cursors"]["lobby"] == 500
    assert state["metrics"]["message_gaps"] == 1
    assert state["metrics"]["estimated_missing_messages"] == 99
    assert state["metrics"]["unrecoverable_gap_events"] == 1
    assert state["metrics"]["unrecoverable_gap_messages"] == 99
    assert state["metrics"]["unrecoverable_retained_ring_start_events"] == 1
    assert state["metrics"]["unrecoverable_retained_ring_start_messages"] == 99
    assert state["metrics"]["unrecoverable_not_in_retained_export_events"] == 0
    assert state["metrics"]["gap_recovered_messages"] == 101
    gap = next(
        item
        for item in state["opportunities"]
        if item.get("kind") == "message_gap"
    )
    assert gap["missing_from"] == 101
    assert gap["missing_to"] == 199
    assert gap["recovery"] == "unrecoverable"
    assert gap["recovery_reason"] == "retained_ring_start"


def test_internal_export_hole_marks_only_missing_interval_then_recovers_tail(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()
    state["cursors"]["lobby"] = 100
    client = ExportClient(export_body_ranges((101, 150), (160, 500)))

    changed, _ = run_recovery(
        client,
        state,
        config,
        [message(seq) for seq in range(301, 501)],
    )

    assert changed is True
    assert state["cursors"]["lobby"] == 500
    assert state["metrics"]["message_gaps"] == 1
    assert state["metrics"]["estimated_missing_messages"] == 9
    assert state["metrics"]["unrecoverable_gap_messages"] == 9
    assert state["metrics"]["unrecoverable_not_in_retained_export_events"] == 1
    assert state["metrics"]["unrecoverable_not_in_retained_export_messages"] == 9
    assert state["metrics"]["gap_recovered_messages"] == 191
    gap = next(
        item
        for item in state["opportunities"]
        if item.get("kind") == "message_gap"
    )
    assert gap["missing_from"] == 151
    assert gap["missing_to"] == 159
    assert gap["recovery_reason"] == "not_in_retained_export"
    assert len(client.calls) == 1


def test_export_failure_does_not_advance_cursor(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()
    state["cursors"]["lobby"] = 100
    client = ExportClient("", status=503)

    changed, drain = run_recovery(
        client,
        state,
        config,
        [message(seq) for seq in range(301, 501)],
    )

    assert changed is True
    assert drain is False
    assert state["cursors"]["lobby"] == 100
    assert state["metrics"]["message_gaps"] == 0
    assert state["health"]["current"] == "degraded"
    assert state["health"]["rooms"]["lobby"]["kind"].startswith("gap_recovery_")


def test_optional_tclk_error_is_visible_but_does_not_degrade_core_health(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()

    observer_resilience.set_error(
        state,
        "tclk-offers",
        "HTTPStatusError",
        "503",
    )

    assert state["health"]["current"] == "ok"
    assert state["health"]["rooms"]["tclk-offers"]["status"] == "error"
    assert state["health"]["rooms"]["tclk-offers"]["optional"] is True
    assert state["health"]["rooms"]["tclk-offers"]["impact"] == "secondary_lane_only"


def test_core_room_error_still_degrades_and_recovery_ignores_optional_error(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()

    observer_resilience.set_error(state, "tclk-offers", "HTTPStatusError")
    observer_resilience.set_error(state, "lobby", "ReadTimeout")
    assert state["health"]["current"] == "degraded"

    observer_resilience.set_success(state, "lobby")
    assert state["health"]["current"] == "ok"
    assert state["health"]["rooms"]["tclk-offers"]["status"] == "error"


def test_recovered_gap_uses_get_only_and_never_calls_post(monkeypatch, tmp_path):
    config = setup(monkeypatch, tmp_path)
    state = observer_resilience.default_state()
    state["cursors"]["lobby"] = 100
    client = ExportClient(export_body(101, 500))

    monkeypatch.setattr(
        core,
        "post_signed",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("gap recovery must never write")
        ),
    )

    run_recovery(
        client,
        state,
        config,
        [message(seq) for seq in range(301, 501)],
    )

    assert all(call[0].endswith("/export") for call in client.calls)


def test_install_is_idempotent_and_patches_only_read_side_functions(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    observer_resilience.install()
    observer_resilience.install()

    assert observer.default_state is observer_resilience.default_state
    assert observer.set_error is observer_resilience.set_error
    assert observer.set_success is observer_resilience.set_success
    assert observer.room_worker is observer_resilience.room_worker
    assert observer.read_room_export is observer_resilience.read_room_export
