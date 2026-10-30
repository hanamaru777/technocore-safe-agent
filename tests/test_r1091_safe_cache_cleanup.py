"""R1091: distinguish regenerable app caches from critical runtime state."""
import importlib.util
import os
from pathlib import Path
import pytest

SRC = Path(__file__).resolve().parents[1] / "packaging/oracle/r1091_safe_cache_cleanup.py"
spec = importlib.util.spec_from_file_location("r1091", SRC)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def test_scan_exact_candidate_only(tmp_path):
    app, state = tmp_path / "app", tmp_path / "state"
    app.mkdir(); state.mkdir()
    (app / ".venv").mkdir(); (app / ".venv" / "__pycache__").mkdir()
    (app / ".venv" / "__pycache__" / "KEEP").write_text("original")
    (app / "__pycache__").mkdir(); (app / "__pycache__" / "a.pyc").write_bytes(b"a")
    (app / "src").mkdir(); (app / "src" / "__pycache__").mkdir()
    (app / "src" / "__pycache__" / "b.pyc").write_bytes(b"b")
    (app / "logs").mkdir(); (app / "logs" / "audit.log").write_text("keep")
    (state / "nonces.json").write_text('{"nonce":1}')
    (state / "observer").mkdir(); (state / "observer" / "history").write_bytes(b"important")
    totals, found, count = m.scan_roots(app,state)
    assert count >= 13
    assert set(found) == {str(app / "__pycache__"),str(app / "src" / "__pycache__")}
    assert totals["state_other_PROTECTED"] > 0
    assert totals["app_venv_ACTIVE"] > 0
    assert totals["app_logs_PROTECTED"] > 0
    assert (state / "observer" / "history").read_bytes() == b"important"

def test_no_symlink_traversal_and_hard_boundary(tmp_path):
    app, state = tmp_path/"app",tmp_path/"state"
    app.mkdir();state.mkdir()
    (app/"link").symlink_to(state,target_is_directory=True)
    (state/"critical").write_bytes(b"critical")
    _,found,_=m.scan_roots(app,state)
    assert not found
    with pytest.raises(m.Blocked,match="INVENTORY_BOUND_STOP"):
        m.scan_roots(app,state,limit=1)
    assert (state/"critical").read_bytes()==b"critical"

def test_dangerous_paths_unclassified_as_removable():
    assert m.classify("state",Path("signer/key")) == "state_signer"
    assert m.classify("state",Path("nonces.json")) == "state_other_PROTECTED"
    assert m.classify("app",Path(".venv/__pycache__/cache")) == "app_venv_ACTIVE"
    assert m.classify("app",Path(".git/objects/pack")) == "app_git_PIN_REQUIRED"
    assert m.classify("app",Path("src/__pycache__/foo")) == "app_PROVEN_CACHE"
