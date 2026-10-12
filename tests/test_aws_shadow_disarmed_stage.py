"""Offline regression tests for the DISARMED AWS Flop shadow staging carrier.

No AWS, Git network, sudo, systemd mutation, Flop runtime, or K137 access.
"""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "packaging/aws/stage-flop-shadow.py"


def load_carrier():
    spec = importlib.util.spec_from_file_location("flop_aws_shadow_carrier", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_python_source_compiles_without_running_it():
    compile(SOURCE.read_text(), str(SOURCE), "exec")


def test_exact_source_and_nonoverlapping_paths():
    m = load_carrier()
    assert len(m.EXPECTED) == 40
    assert m.EXPECTED == "3fb667837a8f01d17e97dabfd1a1bfe5ddc09e1e"
    assert m.RELEASE.startswith("/opt/flop-shadow/releases/")
    assert all(x.startswith("/") and "tradebot" not in x for x in m.BASES)
    assert "/var/lib/tradebot-k137-public" not in m.BASES
    assert m.URL == "https://github.com/hanamaru777/technocore-safe-agent.git"


def test_git_context_never_uses_operator_home_or_ssh_credentials():
    env = load_carrier().git_env()
    assert env["HOME"] == "/nonexistent"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_ASKPASS"] == "/bin/false"
    assert env["GIT_SSH_COMMAND"] == "/bin/false"
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"


@pytest.mark.parametrize("mem,psi_mem,psi_io", [
    (699 * 1024, 0, 0),
    (900 * 1024, 5.01, 0),
    (900 * 1024, 0, 10.01),
])
def test_pressure_gate_stops_before_mutation(monkeypatch, mem, psi_mem, psi_io):
    m = load_carrier()
    monkeypatch.setattr(m, "pressure", lambda: (mem, psi_mem, psi_io))
    with pytest.raises(m.Stop, match="HOST_PRESSURE_STOP"):
        m.gate()


@pytest.mark.parametrize("timer_state", [("inactive", "disabled"), ("active", "enabled")])
def test_readonly_k137_off_or_armed_public_timer_is_accepted(monkeypatch, timer_state):
    m = load_carrier()
    monkeypatch.setattr(m.pathlib.Path, "exists", lambda p: True)
    monkeypatch.setattr(m.pwd, "getpwnam", lambda name: SimpleNamespace(pw_name=name))
    monkeypatch.setattr(m, "status", lambda n: timer_state if n.endswith(".timer") else ("inactive", "disabled"))
    assert m.k137() == (("inactive", "disabled"), timer_state)


@pytest.mark.parametrize("timer_state", [("inactive", "enabled"), ("active", "disabled"), ("failed", "enabled")])
def test_readonly_k137_unexpected_timer_state_is_rejected(monkeypatch, timer_state):
    m = load_carrier()
    monkeypatch.setattr(m.pathlib.Path, "exists", lambda p: True)
    monkeypatch.setattr(m.pwd, "getpwnam", lambda name: SimpleNamespace(pw_name=name))
    monkeypatch.setattr(m, "status", lambda n: timer_state if n.endswith(".timer") else ("inactive", "disabled"))
    with pytest.raises(m.Stop, match="K137_TIMER_UNEXPECTED_STATE_STOP"):
        m.k137()


def test_readonly_k137_service_active_is_rejected(monkeypatch):
    m = load_carrier()
    monkeypatch.setattr(m.pathlib.Path, "exists", lambda p: True)
    monkeypatch.setattr(m.pwd, "getpwnam", lambda name: SimpleNamespace(pw_name=name))
    monkeypatch.setattr(m, "status", lambda n: ("active", "disabled") if n.endswith(".service") else ("inactive", "disabled"))
    with pytest.raises(m.Stop, match="K137_SERVICE_NOT_DISARMED_STOP"):
        m.k137()


def test_no_application_dependency_installs_or_service_actions():
    source = SOURCE.read_text()
    for forbidden in ("systemctl start", "systemctl enable", "systemctl restart",
                      "pip install", "apt install", "uv sync", "npm install",
                      "block-technocore-metadata.sh", "InstancePrincipalsSecurityTokenSigner"):
        assert forbidden not in source
    assert "FLOP_SHADOW_DISARMED_STAGE_PASS" in source
    assert "K137_SERVICE_TIMER_UNCHANGED_PASS" in source


def test_ubuntu_syslog_group_writable_log_parent_is_only_exception(monkeypatch):
    m = load_carrier()
    monkeypatch.setattr(m.grp, "getgrnam", lambda n: SimpleNamespace(gr_gid=22))
    monkeypatch.setattr(m.pathlib.Path, "lstat", lambda p: SimpleNamespace(
        st_mode=m.stat.S_IFDIR | 0o775, st_uid=0, st_gid=22
    ))
    m.check_parent("/var/log")
    with pytest.raises(m.Stop, match="UNSAFE_PARENT_STOP_var_cache"):
        m.check_parent("/var/cache")


@pytest.mark.parametrize("uid,gid,mode,is_dir", [
    (5, 22, 0o775, True),
    (0, 999, 0o775, True),
    (0, 22, 0o777, True),
    (0, 22, 0o2775, True),
    (0, 22, 0o775, False),
])
def test_unsafe_log_parent_fails_closed_with_precise_path(
    monkeypatch, uid, gid, mode, is_dir,
):
    m = load_carrier()
    monkeypatch.setattr(m.grp, "getgrnam", lambda n: SimpleNamespace(gr_gid=22))
    filetype = m.stat.S_IFDIR if is_dir else m.stat.S_IFLNK
    monkeypatch.setattr(m.pathlib.Path, "lstat", lambda p: SimpleNamespace(
        st_mode=filetype | mode, st_uid=uid, st_gid=gid
    ))
    with pytest.raises(m.Stop, match="UNSAFE_PARENT_STOP_var_log"):
        m.check_parent("/var/log")


def test_other_root_parent_no_group_or_world_write(monkeypatch):
    m = load_carrier()
    monkeypatch.setattr(m.pathlib.Path, "lstat", lambda p: SimpleNamespace(
        st_mode=m.stat.S_IFDIR | 0o755, st_uid=0, st_gid=0
    ))
    m.check_parent("/var/cache")
