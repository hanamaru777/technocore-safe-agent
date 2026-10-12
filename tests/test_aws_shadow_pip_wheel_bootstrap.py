"""Zero-network, no privileged writes: pip-wheel bootstrap / Flop-only safety tests."""
import importlib.util
import io
from pathlib import Path
import stat
import subprocess
import sys
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "packaging/aws/install-shadow-no-ensurepip-pinned.py"

def load():
    spec = importlib.util.spec_from_file_location("flop_shadow_pip_bootstrap", SOURCE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def make_fake_wheel(path, unsafe=None):
    names = ["pip/__init__.py", "pip/__main__.py",
             "pip-26.2.1.dist-info/METADATA"]
    names += [f"pip/_vendor/local_fake_{i}.py" for i in range(24)]
    if unsafe is not None:
        names.append(unsafe)
    with zipfile.ZipFile(path, "w") as z:
        for name in names:
            z.writestr(name, b"# offline fixture\n")
    return names

def test_new_source_compiles_and_no_ensurepip():
    s = SOURCE.read_text()
    compile(s, str(SOURCE), "exec")
    assert '"-m", "ensurepip"' not in s and '"ensurepip", "--upgrade"' not in s
    assert "PIP_BOOTSTRAP" in s
    assert "FLOP_SHADOW_PINNED_PIP_WHEEL_BOOTSTRAP_PASS" in s
    assert "FLOP_SHADOW_PINNED_RUNTIME_DEPS_STAGE_PASS" in s
    assert "FLOP_SHADOW_RUNTIME_IMPORT_OFFLINE_PASS" in s
    assert "--no-index" in s and "--no-deps" in s and "--no-cache-dir" in s

def test_pip_official_metadata_is_exactly_pinned():
    m = load()
    assert m.PIP_WHEEL == "pip-26.2.1-py3-none-any.whl"
    assert m.PIP_SHA256 == "71138adf1f4ca900cdb7d289c21b7494"\n                            "329f2332b6d85f0e1c42108c0384ed3e"
    assert m.PIP_URL == ("https://files.pythonhosted.org/packages/"
                         "f3/6e/1736e5b4ae2b778ef2f81c47d797de9f891d4d8acb047a24ca37a60294dd/"
                         "pip-26.2.1-py3-none-any.whl")
    assert m.WHEELS.name == "runtime-wheel-cache-v2"
    assert m.PIP_URL.startswith("https://files.pythonhosted.org/")
    assert len(m.PIP_SHA256) == 64

def test_bootstrap_extracts_only_to_owned_venv_under_python(tmp_path):
    m = load()
    site = tmp_path / "site-packages"
    site.mkdir(mode=0o700)
    whl = tmp_path / m.PIP_WHEEL
    make_fake_wheel(whl)
    p = subprocess.run([sys.executable, "-I", "-c", m.PIP_BOOTSTRAP,
                        str(site), str(whl)], capture_output=True, text=True,
                        timeout=10)
    assert p.returncode == 0, p.stderr
    assert (site / "pip" / "__main__.py").is_file()
    assert (site / "pip-26.2.1.dist-info" / "METADATA").is_file()
    assert not (site / ".flop-pip-bootstrap-v1").exists()
    assert "FLOP_SHADOW_PINNED_PIP_WHEEL_BOOTSTRAP_PASS" in p.stdout

@pytest.mark.parametrize("evil", [
    "pip/../../outside.txt",
    "/tmp/absolute.txt",
    "pip/sub/../../../evil.py",
    "some_other_project/unsafe.py",
])
def test_bootstrap_rejects_zip_traversal_and_unrelated_wheels(tmp_path, evil):
    m = load()
    site = tmp_path / "site-packages"
    site.mkdir()
    whl = tmp_path / m.PIP_WHEEL
    make_fake_wheel(whl, unsafe=evil)
    p = subprocess.run([sys.executable, "-I", "-c", m.PIP_BOOTSTRAP,
                        str(site), str(whl)], capture_output=True, text=True,
                        timeout=10)
    assert p.returncode != 0
    assert not (site / "pip").exists()
    assert not (site / ".flop-pip-bootstrap-v1").exists()

def test_bootstrap_rejects_wheel_internal_symlink(tmp_path):
    m = load()
    site = tmp_path / "site-packages"
    site.mkdir()
    whl = tmp_path / m.PIP_WHEEL
    make_fake_wheel(whl)
    with zipfile.ZipFile(whl, "a") as z:
        info = zipfile.ZipInfo("pip/_vendor/attempt_link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        z.writestr(info, "/etc/passwd")
    p = subprocess.run([sys.executable, "-I", "-c", m.PIP_BOOTSTRAP,
                        str(site), str(whl)], capture_output=True, text=True,
                        timeout=10)
    assert p.returncode != 0
    assert not (site / "pip").exists()

def test_k137_and_other_bot_paths_are_not_written():
    s = SOURCE.read_text()
    for pattern in ("systemctl start", "systemctl stop", "systemctl enable",
                    "sudo ", "apt install", "uv sync", "oci.auth",
                    "flop_agent.resident_daemon", "flop_agent.oracle_signer",
                    "tradebot-liquidation", "aerodrome-b1", "wallet_seed"):
        assert pattern not in s
    assert '["runuser", "-u", "flop-shadow"' in s
    assert '"env", "-i"' in s
    assert "headroom()" in s
    assert "K137_SERVICE_TIMER_CHANGED_STOP" in s
    assert "K137_DRIFT_BEFORE_BOOTSTRAP_STOP" in s

def test_k137_window_keeps_18m_until_next_scan():
    from datetime import datetime, timezone
    m = load()
    for minute in (0, 2, 5, 45, 53, 59):
        assert not m.slot_now(datetime(2026,10,12,4,minute,tzinfo=timezone.utc))
    for minute in (6, 10, 38, 44):
        assert m.slot_now(datetime(2026,10,12,4,minute,tzinfo=timezone.utc))
