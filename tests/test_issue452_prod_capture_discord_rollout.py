from pathlib import Path
import re


HELPER = Path('packaging/oracle/issue452-prod-capture-discord-rollout-v1.sh')


def _source() -> str:
    return HELPER.read_text('utf-8')


def test_issue452_rollout_pins_exact_source_and_baseline():
    source = _source()
    assert 'PRE=041b830d3b0ffd17ef95f8d889922f20d3ac6631' in source
    assert 'TARGET=b8c63f865856d5004f8d310eb8ff4c31dbd7ffb0' in source
    assert 'EXPECTED_CORE_EVENTS=121' in source
    assert 'EXPECTED_CORE_MESSAGES=5650187' in source
    assert 'EXPECTED_BRIDGE_EVENTS=4' in source
    assert 'EXPECTED_BRIDGE_MESSAGES=567032' in source
    for path in (
        'src/flop_agent/discord_outcome_scorecard.py',
        'src/flop_agent/observer_lobby_capture.py',
        'tests/test_discord_outcome_scorecard.py',
        'tests/test_observer_lobby_capture.py',
    ):
        assert path in source


def test_issue452_restarts_only_capture_and_discord():
    source = _source()
    assert 'systemctl restart technocore-safe-agent-lobby-capture.service' in source
    assert 'systemctl restart technocore-safe-agent-discord.service' in source
    assert 'systemctl restart technocore-safe-agent-resident.service' not in source
    assert 'systemctl restart technocore-safe-agent-signer.service' not in source
    assert "RESIDENT_RESTART=NO" in source
    assert "SIGNER_RESTART=NO" in source


def test_issue452_has_continuity_and_safety_gates():
    source = _source()
    assert 'MAX_PROTECTED_ROWS == 2_000_000' in source
    assert '120S ACCEPTANCE WATCH' in source
    assert 'lobby_cursor_not_advancing' in source
    assert 'final_observer_not_ok' in source
    assert 'ACTIVE_CAPTURE_SQLITE_QUERY=NO' in source
    assert 'SYNTHETIC_DISCORD_MESSAGE=NO' in source
    assert 'TECHNOCORE_WRITE=NO' in source
    assert 'FLOP_WRITE=NO' in source
    assert 'X_WRITE=NO' in source
    assert 'DO_NOT_RERUN=YES' in source
    assert re.search(r'\bsqlite3\b', source) is None


def test_issue452_uses_ff_only_and_exact_remote_main():
    source = _source()
    assert 'git_owner fetch --no-tags origin main' in source
    assert 'git_owner merge --ff-only "$TARGET"' in source
    assert 'remote_main_moved' in source
    assert 'target_diff_unexpected' in source
