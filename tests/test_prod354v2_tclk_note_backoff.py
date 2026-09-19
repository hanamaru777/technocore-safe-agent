from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "prod354v2-tclk-note-backoff.sh"


def test_prod354v2_helper_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_prod354v2_pins_exact_pre_target_and_allowlist() -> None:
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


def test_prod354v2_registry_check_cannot_hit_pipefail_sigpipe_false_negative() -> None:
    text = HELPER.read_text("utf-8")

    assert "adapter_registry_empty()" in text
    assert 'Path(sys.argv[1])' in text
    assert '_ADAPTERS: dict[str, ExecutionAdapter] = {}' in text
    assert "git_owner show HEAD:src/flop_agent/airdrop_executor.py" not in text
    assert "grep -Fq '_ADAPTERS" not in text
    assert "REGISTRY_CHECK=PYTHON_DIRECT_READ" in text


def test_prod354v2_restarts_only_discord_and_preserves_core_services() -> None:
    text = HELPER.read_text("utf-8")

    assert 'systemctl restart "$DIS"' in text
    assert 'systemctl restart "$RES"' not in text
    assert 'systemctl restart "$CAP"' not in text
    assert 'systemctl restart "$SIG"' not in text

    assert 'unexpected_pid_change:$svc' in text
    assert 'unexpected_restart_change:$svc' in text
    assert "RESIDENT_PRESERVED=" in text
    assert "CAPTURE_PRESERVED=" in text
    assert "SIGNER_PRESERVED=" in text
    assert "DISCORD_RESTARTED=" in text


def test_prod354v2_rolls_back_code_and_reloads_discord_if_post_cutover_fails() -> None:
    text = HELPER.read_text("utf-8")

    assert 'git_owner reset --hard "$PRE"' in text
    assert 'if [[ $DISCORD_RESTARTED -eq 1 ]]' in text
    assert 'systemctl restart "$DIS"' in text
    assert "PROD354V2_ROLLBACK=COMPLETE" in text


def test_prod354v2_isolated_smoke_has_no_network_or_protocol_write() -> None:
    text = HELPER.read_text("utf-8")
    lower = text.lower()

    assert "/tmp/prod354v2-tclk-note." in text
    assert 'FLOP_STATE_DIR="$SMOKE_DIR"' in text
    assert '_retry_delay("full_spec_read_failed",1)==60' in text
    assert '_retry_delay("full_spec_not_found",1)==300' in text
    assert 'reader=lambda _ns,_key: None' in text
    assert 'raise TimeoutError("simulated")' in text

    assert "curl " not in lower
    assert "wget " not in lower
    assert "discord_bot_token" not in lower
    assert "technocore_signing_key" not in lower
    assert "post_signed(" not in lower
    assert "write_note(" not in lower
    assert "accept(" not in lower
    assert "reveal(" not in lower


def test_prod354v2_guards_dormant_airdrop_execution_boundary() -> None:
    text = HELPER.read_text("utf-8")

    assert '[[ $requests == 0 ]]' in text
    assert '[[ $candidates == 0 ]]' in text
    assert '[[ $executions == 0 ]]' in text
    assert "ADAPTER_REGISTRY=EMPTY" in text
    assert "DO_NOT_RERUN=YES" in text
