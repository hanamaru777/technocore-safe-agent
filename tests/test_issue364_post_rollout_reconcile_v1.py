from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue364-post-rollout-reconcile-v1.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_issue364_postv1_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_issue364_postv1_pins_target_and_current_baseline() -> None:
    text = _text()
    for token in (
        "TARGET=9d635be14de715d61e680136dd688bd8598e9403",
        "EXPECTED_CORE_EVENTS=120",
        "EXPECTED_CORE_MESSAGES=5650166",
        "EXPECTED_RES_PID=2195965",
        "EXPECTED_RES_RESTARTS=0",
        "EXPECTED_CAP_PID=1868796",
        "EXPECTED_SIGN_PID=1539554",
        "EXPECTED_DISC_PID=1957840",
    ):
        assert token in text


def test_issue364_postv1_is_read_only() -> None:
    text = _text().lower()
    for forbidden in (
        "git fetch",
        "git merge",
        "git pull",
        "git reset",
        "git checkout",
        "chmod ",
        "chown ",
        "systemctl restart",
        "systemctl stop",
        "systemctl start",
        "kill -",
        "pkill ",
        "killall ",
        "sqlite3",
        "lobby-capture.sqlite3",
        "httpx",
        "curl ",
        "wget ",
        "client.post(",
        "post_signed(",
        "write_note(",
    ):
        assert forbidden not in text


def test_issue364_postv1_samples_stability_pressure_and_children() -> None:
    text = _text()
    for token in (
        "sample T0",
        "sample T60",
        "sample T120",
        "PRESSURE_GUARD_CURRENT=",
        "RESOURCE_TRACKER_CHILD_COUNT=",
        "MAINTENANCE_CHILD_COUNT=",
        "MAINTENANCE_CHILD_STATES=",
        "FINAL_PROTECTED_CORE=",
        "FINAL_OBSERVER_HEARTBEAT_AGE=",
        "FINAL_OBSERVER_UPDATED_MOVED=",
        "FINAL_CURSOR_NONDECREASING=",
    ):
        assert token in text


def test_issue364_postv1_pins_runtime_permissions_and_blobs() -> None:
    text = _text()
    for token in (
        "CAPTURE_BLOB=285a95c539611c87768634cba1d45cdb442beb14",
        "BRIDGE_BLOB=b96f315dd6bd5c2baa0f5db35acd85479e52e993",
        "ISOLATION_BLOB=6ea86a3f7350162727763e58f95116970eb43f35",
        '[[ "$blob" == "$expected" && "$mode" == 644 && "$owner" == root && "$group" == root ]]',
    ):
        assert token in text


def test_issue364_postv1_acceptance_is_strict_on_continuity() -> None:
    text = _text()
    for token in (
        "protected_core_changed_before_watch",
        "resident_not_stable",
        "protected_core_changed_during_watch",
        "observer_not_progressing",
        "observer_heartbeat_not_fresh",
        "=== ISSUE364_POST_ROLLOUT_RECONCILE_V1=PASS ===",
    ):
        assert token in text


def test_issue364_postv1_no_raw_sensitive_process_output() -> None:
    text = _text()
    assert "RAW_CMDLINE_OUTPUT=NO" in text
    assert "PROCESS_ENV_OUTPUT" not in text
    assert "cat /proc/" not in text


def test_issue364_postv1_safety_tail() -> None:
    text = _text()
    for token in (
        "SERVICE_MUTATION=NO",
        "SERVICE_RESTART=NO",
        "SOURCE_MUTATION=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
        "NETWORK_PROBE=NO",
        "TECHNOCORE_WRITE=NO",
        "DO_NOT_RERUN=YES",
    ):
        assert token in text
