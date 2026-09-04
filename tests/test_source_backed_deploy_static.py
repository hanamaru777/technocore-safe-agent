from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packaging" / "oracle" / "deploy-source-backed-v1.sh"


def test_source_backed_cutover_has_valid_bash_syntax() -> None:
    result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_source_backed_cutover_is_exact_sha_and_signer_safe() -> None:
    text = SCRIPT.read_text("utf-8")

    assert "PRE_EXPECTED=3d90733d046dc24bef374e649893fe88e9003b49" in text
    assert "git fetch origin main" in text
    assert '[[ $REMOTE == "$TARGET" ]]' in text
    assert 'git diff --name-only "$PRE..$TARGET"' in text
    assert 'git merge --ff-only "$TARGET"' in text
    assert "production worktree is not clean" in text

    for expected in (
        "SOURCES.md",
        "docs/source-backed-onboarding-v1.md",
        "knowledge/registry-v1.json",
        "packaging/oracle/discord.service",
        "packaging/oracle/deploy-source-backed-v1.sh",
        "src/flop_agent/discord_knowledge.py",
        "src/flop_agent/knowledge.py",
        "src/flop_agent/knowledge_guard.py",
        "src/flop_agent/resident_daemon.py",
        "tests/test_collaboration_hardening.py",
        "tests/test_source_backed_deploy_static.py",
        "tests/test_source_backed_discord.py",
        "tests/test_source_backed_knowledge.py",
    ):
        assert expected in text

    assert 'systemctl restart "$RESIDENT"' in text
    assert 'systemctl restart "$DISCORD"' in text
    assert 'systemctl restart "$SIGNER"' not in text
    assert 'SIGNER_PID_POST == "$SIGNER_PID_PRE"' in text
    assert 'SIGNER_RESTARTS_POST == "$SIGNER_RESTARTS_PRE"' in text
    assert 'SIGNER_PID_FINAL == "$SIGNER_PID_PRE"' in text
    assert 'SIGNER_RESTARTS_FINAL == "$SIGNER_RESTARTS_PRE"' in text


def test_source_backed_cutover_preserves_frozen_write_state() -> None:
    text = SCRIPT.read_text("utf-8")

    assert "flop_agent.cli autopilot-pause" in text
    assert "RECEIPTS_PRE -eq 2" in text
    assert "QUEUED_PRE -eq 0" in text
    assert 'OUTBOX_HASH_POST == "$OUTBOX_HASH_PRE"' in text
    assert "Autopilot remains paused" in text
    assert "autopilot-resume" not in text
    assert "autopilot-publish" not in text
    assert "post-signed" not in text
    assert "stage-e2e" not in text
    assert "update.sh" not in text


def test_source_backed_cutover_acceptance_covers_required_boundaries() -> None:
    text = SCRIPT.read_text("utf-8")

    assert "summary['topics'] == 7" in text
    assert "summary['verified'] == 7" in text
    assert "summary['signable'] == 6" in text
    assert "summary['stale'] == []" in text
    assert "topic_status('tclk_alpha')" in text
    assert "tclk['signable'] is False" in text
    assert "unsupported_current_or_reward_fact" in text
    assert "'/knowledge'" in text
    assert "'/knowledge nonce'" in text
    assert "'/knowledge tclk_alpha'" in text
    assert "'/candidate acceptance-local-only'" in text
    assert "resident.candidate = lambda _candidate_id: {'untrusted_data': True, 'candidate': synthetic}" in text
    assert "Knowledge: tclk_alpha | verified | read-only" in text
    assert "'/collab'" in text
    assert "'/status'" in text

    assert "AUTOPILOT_AUDIT_GROWTH" in text
    assert "combined Resident+Discord CPU exceeded 120%" in text
    assert "GATEWAY_LAG_MARKERS" in text
    assert "new Observer gap regression detected" in text
    assert "KNOWLEDGE_DEPLOY=PASS" in text


def test_source_backed_cutover_rolls_back_only_non_signer_services() -> None:
    text = SCRIPT.read_text("utf-8")
    rollback = text.split("rollback() {", 1)[1].split("trap rollback EXIT", 1)[0]

    assert 'git reset --hard "$PRE"' in rollback
    assert 'systemctl restart "$RESIDENT"' in rollback
    assert 'systemctl restart "$DISCORD"' in rollback
    assert 'systemctl restart "$SIGNER"' not in rollback
    assert "Signer untouched" in rollback
