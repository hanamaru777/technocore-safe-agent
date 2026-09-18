from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "prod333-airdrop-staging-bridge.sh"


def test_prod333_helper_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_prod333_helper_pins_exact_rollout_and_no_long_running_restart() -> None:
    text = HELPER.read_text("utf-8")

    assert "PRE=52f71d77fd79c8fb3cf3a53d94205ec7ec5888b7" in text
    assert "TARGET=cd8e91d26f06c2de3a549f5e8c22a65bfc38711c" in text
    assert "CORE_EVENTS=117" in text
    assert "CORE_MESSAGES=5083155" in text

    for path in (
        "src/flop_agent/airdrop_action_stager.py",
        "src/flop_agent/airdrop_monitor.py",
        "src/flop_agent/airdrop_notifier.py",
        "tests/test_airdrop_action_stager.py",
    ):
        assert path in text

    assert "lobby-capture-service.sqlite3" not in text
    assert "sqlite3" not in text
    assert 'systemctl restart "$RES"' not in text
    assert 'systemctl restart "$CAP"' not in text
    assert 'systemctl restart "$SIG"' not in text
    assert 'systemctl restart "$DIS"' not in text
    assert 'systemctl restart "$MON_TIMER"' not in text
    assert 'systemctl restart "$NOT_TIMER"' not in text
    assert 'git_owner merge --ff-only "$TARGET"' in text
    assert 'systemctl start "$MON_SVC"' in text
    assert "STAGING_OUTCOME=$POST_STAGING" in text
    assert "STAGED_APPROVALS=$POST_STAGED" in text
    assert "DO_NOT_RERUN=YES" in text


def test_prod333_helper_has_no_protocol_write_or_secret_transport() -> None:
    lowered = HELPER.read_text("utf-8").lower()

    assert "technocore_signing_key" not in lowered
    assert "oracle_signer" not in lowered
    assert "discord_bot_token" not in lowered
    assert "client.post" not in lowered
    assert "curl " not in lowered
    assert "wget " not in lowered
    assert "post-signed" not in lowered
    assert "publish-approved" not in lowered
