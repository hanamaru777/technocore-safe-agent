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
    assert "/var/lib/technocore-safe-agent/signer" in unit.split("ReadWritePaths=", 1)[1]
    assert 'install -d -o technocore-signer -g technocore-signer -m 0700 "$state/signer/uv-cache"' in prepare


def test_public_hash_assignment_is_not_treated_as_secret():
    public_hash = "a" * 64
    line = f'EXPECTED_POEM_SHA="{public_hash}"'
    assert core.PUBLIC_HASH_ASSIGNMENT_RE.search(line)
    assert core.SECRET_PATTERN.search(line)


def test_secret_named_hex_assignment_is_not_whitelisted_as_public_hash():
    secret = "b" * 64
    line = f'SIGN_SEED="{secret}"'
    assert core.SECRET_PATTERN.search(line)
    assert core.PUBLIC_HASH_ASSIGNMENT_RE.search(line) is None


def test_unrelated_hash_named_secret_is_not_public_hash_whitelisted():
    value = "c" * 64
    line = f'PRIVATE_KEY_HASH="{value}"'
    assert core.SECRET_PATTERN.search(line)
    assert core.PUBLIC_HASH_ASSIGNMENT_RE.search(line) is None


def test_expected_sha_and_poem_sha_are_explicitly_supported():
    value = "d" * 64
    assert core.PUBLIC_HASH_ASSIGNMENT_RE.search(f'EXPECTED_SHA="{value}"')
    assert core.PUBLIC_HASH_ASSIGNMENT_RE.search(f'POEM_SHA="{value}"')
