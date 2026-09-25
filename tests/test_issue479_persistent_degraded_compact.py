from pathlib import Path
import re

HELPER=Path('packaging/oracle/issue479-persistent-degraded-compact-v1.sh')

def _source():
    return HELPER.read_text('utf-8')

def test_prod479_pins_current_runtime_and_baseline():
    s=_source()
    assert 'EXPECTED_HEAD=9baa91be7267b22143c33a06df3c67e1074dba0d' in s
    assert 'RES_PID=2256397' in s
    assert 'CAP_PID=2405706' in s
    assert 'SIG_PID=2256324' in s
    assert 'DIS_PID=2438454' in s
    assert 'CORE_E=124' in s and 'CORE_M=5651120' in s
    assert 'BRIDGE_E=7' in s and 'BRIDGE_M=567965' in s

def test_prod479_is_compact_read_only_watch():
    s=_source()
    assert 'for phase in T0 T60 T120' in s
    assert 'errors15m:' in s
    assert 'classification:' in s
    assert s.count('echo "') <= 12
    for marker in (
        'SAFETY=mutation:NO',
        'restart:NO',
        'sqlite:NO',
        'network:NO',
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
