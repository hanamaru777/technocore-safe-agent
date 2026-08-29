from pathlib import Path

from flop_agent import core


ROOT = Path(__file__).resolve().parents[1]


def test_bundled_official_signer_matches_pinned_git_blob():
    assert core.signer_matches_pinned()


def test_no_tracked_secret_material():
    assert core.secret_scan() == []


def test_no_secret_material_in_reachable_git_history():
    assert core.history_secret_scan() == []


def test_doctor_reports_required_checks(monkeypatch):
    monkeypatch.setattr(core, "find_uv", lambda: "uv")
    class Result:
        returncode = 0
        stdout = "uv 1.0"
    monkeypatch.setattr(core.subprocess, "run", lambda *args, **kwargs: Result())
    monkeypatch.setattr(core, "git_commit_sha", lambda: "a" * 40)
    report = core.doctor()
    assert report["checks"]["uv_found"] is True
    assert report["checks"]["official_signer_matches_pinned"] is True


def test_oracle_signer_has_private_writable_uv_cache():
    unit = (ROOT / "packaging/oracle/technocore-safe-agent-signer.service").read_text("utf-8")
    prepare = (ROOT / "packaging/oracle/prepare-signer.sh").read_text("utf-8")
    cache = "/var/lib/technocore-safe-agent/signer/uv-cache"
    assert f"Environment=UV_CACHE_DIR={cache}" in unit
    assert cache in unit.split("ReadWritePaths=", 1)[1]
    assert 'install -d -o technocore-signer -g technocore-signer -m 0700 "$state/signer/uv-cache"' in prepare
