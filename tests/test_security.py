from flop_agent import core


def test_bundled_official_signer_hash_is_pinned():
    assert core.signer_sha256() == core.SIGNER_SHA256


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
