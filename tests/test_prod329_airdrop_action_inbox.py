from __future__ import annotations

import subprocess
from pathlib import Path

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "prod329-airdrop-action-inbox.sh"


def test_prod329_helper_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_prod329_helper_is_exact_discord_only_rollout() -> None:
    text = HELPER.read_text("utf-8")

    assert "PRE=a114d4d414f20009088a6ca150044b0f75e52d26" in text
    assert "TARGET=52f71d77fd79c8fb3cf3a53d94205ec7ec5888b7" in text
    assert "CORE_EVENTS=117" in text
    assert "CORE_MESSAGES=5083155" in text

    for path in (
        "src/flop_agent/airdrop_approval.py",
        "src/flop_agent/discord_control.py",
        "src/flop_agent/discord_tclk_approval.py",
        "tests/test_airdrop_approval.py",
    ):
        assert path in text

    assert "lobby-capture-service.sqlite3" not in text
    assert "sqlite3" not in text
    assert "systemctl restart \"$RES\"" not in text
    assert "systemctl restart \"$CAP\"" not in text
    assert "systemctl restart \"$SIG\"" not in text
    assert 'systemctl restart "$DIS"' in text
    assert 'git_owner merge --ff-only "$TARGET"' in text
    assert "ACTION_INBOX_LOCAL_SMOKE=PASS" in text
    assert "FLOP_EXTERNAL_WRITE=NO" in text
    assert "DO_NOT_RERUN=YES" in text


def test_prod329_helper_has_no_protocol_or_secret_transport() -> None:
    text = HELPER.read_text("utf-8")
    lowered = text.lower()

    assert "technocore_signing_key" not in lowered
    assert "oracle_signer" not in lowered
    assert "discord_bot_token" not in lowered
    assert "client.post" not in lowered
    assert "curl " not in lowered
    assert "wget " not in lowered
