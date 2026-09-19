from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "prod342-airdrop-executor-gate.sh"


def test_prod342_helper_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_prod342_helper_pins_exact_dormant_rollout() -> None:
    text = HELPER.read_text("utf-8")

    assert "PRE=9e69f0e33f29c2e39bbda8b61e6a098480192ae5" in text
    assert "TARGET=2d140ccf5334b709876c2c4f3223649898ef2dc8" in text
    assert "CORE_EVENTS=117" in text
    assert "CORE_MESSAGES=5083155" in text

    for path in (
        "src/flop_agent/airdrop_approval.py",
        "src/flop_agent/airdrop_executor.py",
        "tests/test_airdrop_executor.py",
    ):
        assert path in text

    assert 'systemctl restart "$RES"' not in text
    assert 'systemctl restart "$CAP"' not in text
    assert 'systemctl restart "$SIG"' not in text
    assert 'systemctl restart "$DIS"' not in text
    assert 'systemctl restart "$MON_TIMER"' not in text
    assert 'systemctl restart "$NOT_TIMER"' not in text
    assert 'git_owner merge --ff-only "$TARGET"' in text

    assert "/tmp/prod342-executor." in text
    assert 'FLOP_STATE_DIR="$SMOKE_DIR"' in text
    assert "airdrop_executor._ADAPTERS == {}" in text
    assert "airdrop_executor_adapter_unavailable" in text
    assert "ADAPTER_REGISTRY=EMPTY" in text
    assert "SERVICE_RESTART=NO" in text
    assert "DO_NOT_RERUN=YES" in text


def test_prod342_helper_has_no_protocol_write_or_active_capture_query() -> None:
    lowered = HELPER.read_text("utf-8").lower()

    assert "lobby-capture-service.sqlite3" not in lowered
    assert "sqlite3" not in lowered
    assert "technocore_signing_key" not in lowered
    assert "oracle_signer" not in lowered
    assert "discord_bot_token" not in lowered
    assert "client.post" not in lowered
    assert "channel.send" not in lowered
    assert "curl " not in lowered
    assert "wget " not in lowered
    assert "post-signed" not in lowered
    assert "publish-approved" not in lowered


def test_prod342_helper_guards_zero_production_executor_state() -> None:
    text = HELPER.read_text("utf-8")
    assert '"$AIRDROP_DIR/action-executions.json"' in text
    assert '[[ $executions == 0 ]]' in text
    assert '[[ $requests == 0 ]]' in text
    assert '[[ $candidates == 0 ]]' in text
    assert '[[ $pending == 0 ]]' in text
