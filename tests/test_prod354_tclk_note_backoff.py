from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "prod354-tclk-note-backoff.sh"


def test_prod354_helper_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_prod354_helper_pins_exact_pre_target_and_allowlist() -> None:
    text = HELPER.read_text("utf-8")

    assert "PRE=3fd5ce445692cc2f94a574c012c080048f96d755" in text
    assert "TARGET=b7bf27dbaa605971d340aa926fdffc17489c3afe" in text
    assert "CORE_EVENTS=117" in text
    assert "CORE_MESSAGES=5083155" in text

    for path in (
        "src/flop_agent/discord_tclk_review.py",
        "src/flop_agent/tclk_note_review.py",
        "src/flop_agent/tclk_review_evidence.py",
        "tests/test_tclk_auto_review_evidence.py",
        "tests/test_tclk_note_review.py",
    ):
        assert path in text

    assert 'git_owner merge --ff-only "$TARGET"' in text


def test_prod354_restarts_only_discord() -> None:
    text = HELPER.read_text("utf-8")

    assert 'systemctl restart "$DIS"' in text

    for service_var in ("$RES", "$CAP", "$SIG", "$MON_TIMER", "$NOT_TIMER"):
        assert f'systemctl restart "{service_var}"' not in text
        assert f'systemctl stop "{service_var}"' not in text

    assert "RESIDENT_PRESERVED=" in text
    assert "CAPTURE_PRESERVED=" in text
    assert "SIGNER_PRESERVED=" in text
    assert "DISCORD_RESTARTED=" in text


def test_prod354_smoke_is_local_and_classifies_retry_reasons() -> None:
    text = HELPER.read_text("utf-8")
    lowered = text.lower()

    assert "/tmp/prod354-tclk-note." in text
    assert 'FLOP_STATE_DIR="$SMOKE_DIR"' in text
    assert '_retry_delay("full_spec_read_failed",1)==60' in text
    assert '_retry_delay("full_spec_not_found",1)==300' in text
    assert 'str(error)=="full_spec_not_found"' in text
    assert 'str(error)=="full_spec_read_failed"' in text
    assert "ISOLATED_TCLK_NOTE_SMOKE=PASS" in text

    assert "curl " not in lowered
    assert "wget " not in lowered
    assert "discord_bot_token" not in lowered
    assert "technocore_signing_key" not in lowered


def test_prod354_has_no_tclk_or_protocol_write_path() -> None:
    lowered = HELPER.read_text("utf-8").lower()

    for forbidden in (
        "sqlite3",
        "lobby-capture-service.sqlite3",
        "post_signed(",
        "write_note(",
        "execute_prepared(",
        "tclk_pilot_accept",
        "tclk_pilot_reveal_publish",
        "oracle_signer",
        "sign_seed",
    ):
        assert forbidden not in lowered

    assert "TCLK_ACCEPT=NO" in HELPER.read_text("utf-8")
    assert "TCLK_REVEAL=NO" in HELPER.read_text("utf-8")
    assert "TCLK_VALUE=NO" in HELPER.read_text("utf-8")
    assert "SIGNER_CALL=NO" in HELPER.read_text("utf-8")


def test_prod354_preserves_action_executor_boundary() -> None:
    text = HELPER.read_text("utf-8")

    assert '[[ $requests == 0 ]]' in text
    assert '[[ $candidates == 0 ]]' in text
    assert '[[ $executions == 0 ]]' in text
    assert "_ADAPTERS: dict[str, ExecutionAdapter] = {}" in text
    assert "ADAPTER_REGISTRY=EMPTY" in text


def test_prod354_rollback_is_repo_and_discord_only() -> None:
    text = HELPER.read_text("utf-8")

    assert 'git_owner reset --hard "$PRE"' in text
    assert 'if [[ $DISCORD_RESTARTED -eq 1 ]]' in text
    assert 'systemctl restart "$DIS"' in text
    assert "PROD354_ROLLBACK=COMPLETE" in text
    assert "DO_NOT_RERUN=YES" in text
