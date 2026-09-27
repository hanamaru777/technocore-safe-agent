from pathlib import Path
import re
import subprocess

G=Path("packaging/oracle/close1-standalone-pressure-gate.sh")
S=Path("packaging/oracle/technocore-safe-agent-close1-standalone-watch.service")
T=Path("packaging/oracle/technocore-safe-agent-close1-standalone-watch.timer")


def test_pressure_gate_is_loose_but_fail_closed():
    x=G.read_text("utf-8")
    assert "m >= 131072" in x
    assert "mp <= 30" in x
    assert "ip <= 50" in x
    assert "/proc/meminfo" in x
    assert "/proc/pressure/memory" in x
    assert "/proc/pressure/io" in x


def test_service_is_short_lived_hardened_and_reuses_existing_env():
    x=S.read_text("utf-8")
    assert "Type=oneshot" in x
    assert "User=technocore" in x
    assert "EnvironmentFile=/etc/technocore-safe-agent/env" in x
    assert "ExecCondition=/bin/sh /opt/technocore-safe-agent/packaging/oracle/close1-standalone-pressure-gate.sh" in x
    assert "python -m flop_agent.close1_standalone_watch" in x
    assert "MemoryMax=192M" in x
    assert "CPUQuota=50%" in x
    assert "NoNewPrivileges=true" in x
    assert "ProtectSystem=strict" in x
    assert "ReadWritePaths=/var/lib/technocore-safe-agent/observer" in x


def test_timer_runs_every_five_minutes():
    x=T.read_text("utf-8")
    assert "OnUnitActiveSec=5min" in x
    assert "AccuracySec=15s" in x


def test_no_restart_or_signing_surface():
    combined="\n".join(p.read_text("utf-8") for p in (G,S,T))
    for pat in (
        r"systemctl restart",
        r"sqlite3",
        r"journalctl",
        r"SIGN_SEED",
        r"OCI_VAULT_SECRET_OCID",
        r"say-signed",
        r"post_message",
    ):
        assert re.search(pat,combined,re.I) is None


def test_shell_gate_syntax():
    r=subprocess.run(["sh","-n",str(G)],capture_output=True,text=True)
    assert r.returncode==0,r.stderr
