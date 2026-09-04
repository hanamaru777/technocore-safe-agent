from pathlib import Path
import re


SCRIPT = Path("packaging/oracle/deploy-collaboration-v1.sh")


def text() -> str:
    return SCRIPT.read_text("utf-8")


def test_collaboration_deploy_is_exact_sha_and_selective():
    value = text()
    assert "pass the exact 40-hex reviewed main SHA" in value
    assert "REMOTE == \"$TARGET\"" in value or "[[ $REMOTE == \"$TARGET\" ]]" in value
    assert "git merge --ff-only \"$TARGET\"" in value
    assert "ALLOWED_RE=" in value
    assert "packaging/oracle/discord\\.service" in value
    assert "pyproject" not in value


def test_collaboration_deploy_never_restarts_resident_or_signer():
    value = text()
    assert 'systemctl restart "$DISCORD"' in value
    forbidden = re.compile(r"systemctl\s+(?:try-)?restart[^\n]*(?:resident|signer)", re.I)
    assert forbidden.search(value) is None
    assert "RESIDENT_PID_PRE" in value and "RESIDENT_PID_POST" in value
    assert "SIGNER_PID_PRE" in value and "SIGNER_PID_POST" in value
    assert "NRestarts" in value


def test_collaboration_deploy_freezes_autopilot_and_requires_empty_queue():
    value = text()
    assert "autopilot-pause" in value
    assert "QUEUE" in value
    assert "queue is not empty after pause" in value
    assert "OUTBOX_HASH_PRE" in value and "OUTBOX_HASH_POST" in value
    assert "Autopilot queue/receipt state changed during cutover" in value
    assert "autopilot-resume" not in value


def test_collaboration_deploy_has_no_technocore_or_tclk_write_surface():
    value = text()
    forbidden = (
        "post-signed",
        "autopilot-publish",
        "tclk_accept",
        "tclk_make_offer",
        "tclk_post_frame",
        "curl https://technocore.chat",
    )
    for token in forbidden:
        assert token not in value
    assert "include_tclk=False" in value
    assert "Local-only reconciliation" in value


def test_collaboration_deploy_checks_real_contact_and_rolls_back_discord_only():
    value = text()
    assert "dce534babcc3e50d7e5e" in value
    assert "first acknowledged contact did not reconstruct as contacted" in value
    assert "ROLLBACK: attempted Discord-only rollback" in value
    assert 'cp -a "$UNIT_BACKUP" "$UNIT"' in value
    assert "git reset --hard \"$PRE\"" in value
    assert "GATEWAY_LAG_MARKERS" in value
    assert "COLLAB_DEPLOY=PASS" in value
