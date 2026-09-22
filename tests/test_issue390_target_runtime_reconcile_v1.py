from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "issue390-target-runtime-reconcile-v1.sh"


def _text() -> str:
    return HELPER.read_text("utf-8")


def test_target_runtime_reconcile_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_target_runtime_reconcile_pins_target_and_runtime_blobs() -> None:
    text = _text()

    for token in (
        "TARGET=473e4f73426069c682cfd716f611e0bfad7d4fe8",
        "EXPECTED_TARGET_CAPTURE_BLOB=285a95c539611c87768634cba1d45cdb442beb14",
        "EXPECTED_TARGET_BRIDGE_BLOB=b96f315dd6bd5c2baa0f5db35acd85479e52e993",
        "EXPECTED_TARGET_ISOLATION_BLOB=6ac40ac32108e141320c1d87d5ce0268e71e986b",
        "ISSUE390_TARGETREC_V1=STOP:repo_not_exact_target",
    ):
        assert token in text


def test_target_runtime_reconcile_compares_process_start_to_reflog() -> None:
    text = _text()

    for token in (
        'reflog","-n","30","--format=%H|%ct|%gs","HEAD"',
        "TARGET_FIRST_CONTIGUOUS_REFLOG_EPOCH=",
        "RESIDENT_PROCESS_START_EPOCH=",
        "RESIDENT_START_MINUS_TARGET_REFLOG_SECONDS=",
        "RUNTIME_PROVENANCE=PROVEN_PRE_TARGET",
        "RUNTIME_PROVENANCE=PROVEN_POST_TARGET",
        "RUNTIME_PROVENANCE=AMBIGUOUS_SAME_SECOND",
        "RUNTIME_PROVENANCE=UNKNOWN_NO_TARGET_REFLOG",
    ):
        assert token in text


def test_target_runtime_reconcile_only_reads_resident_immediate_children() -> None:
    text = _text()

    assert 'f"/proc/{pid}/task/{pid}/children"' in text
    assert "RESIDENT_IMMEDIATE_CHILD_COUNT=" in text
    assert "RESIDENT_CHILD pid=" in text
    assert 'pathlib.Path("/proc").iterdir()' not in text


def test_target_runtime_reconcile_reads_continuity_and_pressure() -> None:
    text = _text()

    for token in (
        "PROTECTED_CORE=",
        "PROTECTED_CORE_MATCH_EXPECTED=",
        "LOBBY_CURSOR=",
        "OBSERVER_HEARTBEAT_AGE=",
        "RESIDENT_HEARTBEAT_AGE=",
        'pathlib.Path("/proc/meminfo")',
        'pathlib.Path(f"/proc/pressure/{kind}")',
    ):
        assert token in text


def test_target_runtime_reconcile_has_no_mutation_or_sensitive_process_reads() -> None:
    text = _text().lower()

    for forbidden in (
        "systemctl restart",
        "systemctl stop",
        "systemctl start",
        "git merge",
        "git reset",
        "git pull",
        "git checkout",
        "sqlite3",
        "httpx",
        "curl ",
        "wget ",
        "kill -",
        "pkill ",
        "killall ",
        "strace ",
        "gdb ",
        "/cmdline",
        "/environ",
        "client.post(",
        "post_signed(",
        "write_note(",
    ):
        assert forbidden not in text


def test_target_runtime_reconcile_safety_tail() -> None:
    text = _text()

    for token in (
        "MUTATION_COMMANDS=NONE",
        "SERVICE_RESTART=NO",
        "PROCESS_SIGNAL=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO",
        "NETWORK_PROBE=NO",
        "RAW_CMDLINE_OUTPUT=NO",
        "PROCESS_ENV_OUTPUT=NO",
        "TECHNOCORE_WRITE=NO",
        "DO_NOT_RERUN=YES",
    ):
        assert token in text
