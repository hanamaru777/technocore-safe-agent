from pathlib import Path
import re

HELPER = Path("packaging/oracle/issue515-core143-bridge-attribution-v1.sh")


def _source():
    return HELPER.read_text("utf-8")


def test_prod515_pins_accepted_baselines_and_exact_match_math():
    s=_source()
    assert "base_core=(124,5651120)" in s
    assert "base_bridge=(7,567965)" in s
    assert "exact_match" in s
    assert "lobby_startup_bridge_unrecoverable_events" in s
    assert "lobby_startup_bridge_unrecoverable_messages" in s


def test_prod515_reads_bridge_recovery_metrics_and_last_gap():
    s=_source()
    for token in (
        "lobby_startup_bridge_attempts",
        "lobby_startup_bridge_successes",
        "lobby_startup_bridge_failures",
        "lobby_startup_bridge_local_suffix_handoffs",
        "lobby_startup_bridge_avoided_unrecoverable_messages",
        "lobby_spool_catchup_waits",
        "lobby_spool_catchup_successes",
        "lobby_spool_catchup_timeouts",
        "last_unrecoverable_gap",
        "error_history",
    ):
        assert token in s


def test_prod515_is_persisted_state_only():
    s=_source()
    assert "MUTATION=NONE" in s
    assert "DO_NOT_RERUN=YES" in s
    for pattern in (
        r"\bcurl\b", r"\bwget\b", r"\bjournalctl\b", r"\bsqlite3\b",
        r"systemctl\s+(?:restart|start|stop)",
        r"git\s+(?:fetch|pull|merge|checkout|reset)",
        r"SIGN_SEED", r"OCI_VAULT_SECRET_OCID",
    ):
        assert re.search(pattern,s) is None
