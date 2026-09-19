from __future__ import annotations

import subprocess

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "prod337-discord-action-buttons.sh"


def test_prod337_helper_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_prod337_helper_pins_exact_discord_only_rollout() -> None:
    text = HELPER.read_text("utf-8")

    assert "PRE=cd8e91d26f06c2de3a549f5e8c22a65bfc38711c" in text
    assert "TARGET=9e69f0e33f29c2e39bbda8b61e6a098480192ae5" in text
    assert "CORE_EVENTS=117" in text
    assert "CORE_MESSAGES=5083155" in text

    for path in (
        "src/flop_agent/airdrop_approval.py",
        "src/flop_agent/discord_airdrop_actions.py",
        "src/flop_agent/discord_control.py",
        "src/flop_agent/discord_tclk_approval.py",
        "tests/test_airdrop_approval.py",
        "tests/test_discord_airdrop_actions.py",
    ):
        assert path in text

    assert "lobby-capture-service.sqlite3" not in text
    assert "sqlite3" not in text
    assert 'systemctl restart "$RES"' not in text
    assert 'systemctl restart "$CAP"' not in text
    assert 'systemctl restart "$SIG"' not in text
    assert 'systemctl restart "$MON_TIMER"' not in text
    assert 'systemctl restart "$NOT_TIMER"' not in text
    assert 'systemctl restart "$DIS"' in text
    assert 'git_owner merge --ff-only "$TARGET"' in text
    assert "airdrop_ledger.verify_ledger()" in text
    assert "/tmp/prod337-action-ui." in text
    assert 'FLOP_STATE_DIR="$SMOKE_DIR"' in text
    assert "REAL_DISCORD_MESSAGE=NO" in text
    assert "DO_NOT_RERUN=YES" in text


def test_prod337_helper_has_no_protocol_or_message_transport() -> None:
    lowered = HELPER.read_text("utf-8").lower()

    assert "technocore_signing_key" not in lowered
    assert "oracle_signer" not in lowered
    assert "discord_bot_token" not in lowered
    assert "client.post" not in lowered
    assert "channel.send" not in lowered
    assert "curl " not in lowered
    assert "wget " not in lowered
    assert "post-signed" not in lowered
    assert "publish-approved" not in lowered
