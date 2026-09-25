from pathlib import Path
import re

HELPER=Path('packaging/oracle/issue481-post-reboot-reconcile-v1.sh')

def _source():
    return HELPER.read_text('utf-8')

def test_prod481_pins_source_and_pre_reboot_baseline():
    s=_source()
    assert 'EXPECTED_HEAD=9baa91be7267b22143c33a06df3c67e1074dba0d' in s
    assert 'BASE_CORE_E=124' in s and 'BASE_CORE_M=5651120' in s
    assert 'BASE_BRIDGE_E=7' in s and 'BASE_BRIDGE_M=567965' in s

def test_prod481_accepts_dynamic_post_reboot_pids_but_requires_stability():
    s=_source()
    assert 'RES_PID' in s and 'CAP_PID' in s and 'SIG_PID' in s and 'DIS_PID' in s
    assert '${phase}_resident_changed' in s
    assert '${phase}_capture_changed' in s
    assert '${phase}_signer_changed' in s
    assert '${phase}_discord_changed' in s
    assert 'for phase in T0 T60 T120' in s

def test_prod481_checks_aux_and_classifies_reboot():
    s=_source()
    assert 'technocore-safe-agent-metadata-block.service' in s
    assert 'technocore-safe-agent-airdrop-monitor.timer' in s
    assert 'technocore-safe-agent-airdrop-notifier.timer' in s
    assert 'REBOOT_RECOVERED_STABLE' in s
    assert 'REBOOT_RECOVERED_WITH_NEW_GAP' in s
    assert 'REBOOT_HEALTH_UNSTABLE' in s

def test_prod481_is_compact_read_only():
    s=_source()
    assert s.count('echo "') <= 14
    for marker in (
        'SAFETY=mutation:NO',
        'restart:NO',
        'sqlite:NO',
        'network:NO',
        'journal:NO',
        'signer:NO',
        'external_write:NO',
        'DO_NOT_RERUN=YES',
    ):
        assert marker in s
    for pattern in (
        r'systemctl\s+(?:restart|start|stop|enable|disable|daemon-reload)\b',
        r'git_owner\s+(?:fetch|merge|pull|checkout|reset)\b',
        r'\bsqlite3\b',
        r'\bjournalctl\b',
        r'\bcurl\b',
        r'\bwget\b',
    ):
        assert re.search(pattern,s) is None


def test_prod481_stable_requires_fresh_heartbeat_and_zero_restarts():
    s=_source()
    assert "age <= 180" in s
    assert "HB_FINAL_FRESH" in s
    assert "NR_TOTAL=$((RES_NR+CAP_NR+SIG_NR+DIS_NR))" in s
    assert '\"$NR_TOTAL\" -eq 0' in s
    assert "REBOOT_STATE_REGRESSION" in s
