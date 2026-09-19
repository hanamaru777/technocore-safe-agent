from __future__ import annotations

import json
import subprocess
import sys

from flop_agent import core


HELPER = core.ROOT / "packaging" / "oracle" / "prod346-adapter-readiness.sh"


def test_prod346_helper_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_prod346_helper_pins_exact_repo_only_rollout() -> None:
    text = HELPER.read_text("utf-8")

    assert "PRE=2d140ccf5334b709876c2c4f3223649898ef2dc8" in text
    assert "TARGET=76fbb513a1f9616865c699cd2b78fb7ccbe83f04" in text
    assert "CORE_EVENTS=117" in text
    assert "CORE_MESSAGES=5083155" in text

    for path in (
        "src/flop_agent/airdrop_adapter_readiness.py",
        "src/flop_agent/airdrop_ledger.py",
        "src/flop_agent/airdrop_monitor.py",
        "src/flop_agent/cli.py",
        "tests/test_airdrop_adapter_readiness.py",
    ):
        assert path in text

    assert 'git_owner merge --ff-only "$TARGET"' in text
    assert "airdrop-adapter-readiness" in text
    assert "ADAPTER_REGISTRY=EMPTY" in text
    assert "READINESS=$READINESS_SUMMARY" in text
    assert "SERVICE_RESTART=NO" in text
    assert "DO_NOT_RERUN=YES" in text


def test_prod346_helper_never_restarts_services_or_writes_protocol() -> None:
    lowered = HELPER.read_text("utf-8").lower()

    assert "systemctl restart" not in lowered
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


def test_prod346_readiness_parser_requires_all_actions_blocked() -> None:
    text = HELPER.read_text("utf-8")
    start_marker = "sudo python3 -c '\n"
    end_marker = "\n') || stop readiness_baseline_unexpected"
    start = text.index(start_marker) + len(start_marker)
    end = text.index(end_marker, start)
    script = text[start:end]

    payload = {
        "ledger_valid": True,
        "actions": {
            "faucet": {
                "state": "BLOCKED",
                "blockers": ["not_open:testnet_status:planned"],
            },
            "registration": {
                "state": "BLOCKED",
                "blockers": ["missing_fact:registration_status"],
            },
            "claim": {
                "state": "BLOCKED",
                "blockers": ["e38_unresolved"],
            },
        },
    }
    ok = subprocess.run(
        [sys.executable, "-c", script],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=True,
    )
    assert "faucet=BLOCKED[" in ok.stdout
    assert "registration=BLOCKED[" in ok.stdout
    assert "claim=BLOCKED[" in ok.stdout

    payload["actions"]["faucet"]["state"] = "IMPLEMENTATION_READY"
    blocked = subprocess.run(
        [sys.executable, "-c", script],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
    )
    assert blocked.returncode != 0
    assert "faucet_not_blocked:IMPLEMENTATION_READY" in blocked.stderr


def test_prod346_guards_zero_action_state_and_empty_registry() -> None:
    text = HELPER.read_text("utf-8")
    assert '"$AIRDROP_DIR/action-inbox.json"' in text
    assert '"$AIRDROP_DIR/action-candidates.json"' in text
    assert '"$AIRDROP_DIR/action-executions.json"' in text
    assert '[[ $requests == 0 ]]' in text
    assert '[[ $candidates == 0 ]]' in text
    assert '[[ $executions == 0 ]]' in text
    assert "_ADAPTERS: dict[str, ExecutionAdapter] = {}" in text
