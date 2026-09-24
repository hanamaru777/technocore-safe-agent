from pathlib import Path
import re

HELPER=Path('packaging/oracle/issue467-core124-compact-diag-v1.sh')

def _source():
    return HELPER.read_text('utf-8')

def test_prod467_pins_current_baselines():
    s=_source()
    assert 'EXPECTED_HEAD=62fbd7c34c0671d10bcbb3cd3f86c54937040c7c' in s
    assert 'BASE_CORE_E=121' in s
    assert 'BASE_CORE_M=5650187' in s
    assert 'BASE_BRIDGE_E=4' in s
    assert 'BASE_BRIDGE_M=567032' in s
    assert 'ATTRIBUTION=startup_bridge_exact_match:' in s

def test_prod467_compact_and_read_only():
    s=_source()
    assert s.count('echo "') <= 16
    for marker in (
        'SAFETY=mutation:NO',
        'restart:NO',
        'sqlite:NO',
        'network_probe:NO',
        'signer:NO',
        'external_write:NO',
        'DO_NOT_RERUN=YES',
    ):
        assert marker in s
    for pattern in (
        r'systemctl\s+(?:restart|start|stop|enable|disable|daemon-reload)\b',
        r'git_owner\s+(?:fetch|merge|pull|checkout|reset)\b',
        r'\bsqlite3\b',
        r'\bcurl\b',
        r'\bwget\b',
    ):
        assert re.search(pattern,s) is None

def test_prod467_summarizes_instead_of_dumping():
    s=_source()
    assert 'RECENT_ERRORS=' in s
    assert 'JOURNAL_MATCH_COUNTS=' in s
    assert 'HEALTH_ROOMS_BEGIN' not in s
    assert 'RECENT_ERROR_HISTORY_BEGIN' not in s
    assert 'tail -n' not in s
