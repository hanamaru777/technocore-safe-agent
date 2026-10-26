"""R1064 isolated Linux-only durable attempted-intent journal regressions."""
import json
import os
from pathlib import Path
import fcntl

import pytest

from flop_agent import testnet_journal as j

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux-only durable directory flock")


def directory(tmp_path):
    base = tmp_path / "agent-reservations"
    base.mkdir(mode=0o700)
    return base


def policy():
    return {"max_request_units": 3, "max_day_units": 4, "max_total_units": 6}


def job(identifier, day="2026-11-03", cost=3):
    return {"intent_id": identifier, "utc_day": day,
            "task_class": "public_news_summary", "data_class": "PUBLIC",
            "payload_sha256": "a"*64, "max_test_units": cost}


def test_reserve_unknown_is_durable_across_fresh_snapshot(tmp_path):
    path = directory(tmp_path)
    result = j.reserve_unknown(path, policy(), job("public-news-01"))
    assert result["durable_pre_send_reservation"] == "UNKNOWN_POST"
    assert result["official_faucet_or_inference_send"] == "NO"
    assert result["allow_retry_without_external_reconciliation"] == "NO"
    state = j.snapshot(path)
    assert len(state["items"]) == 1
    assert state["items"][0]["status"] == "UNKNOWN_POST"
    assert (path / "intent-public-news-01.json").stat().st_mode & 0o777 == 0o600


def test_same_intent_cannot_be_resubmitted_after_restart(tmp_path):
    path = directory(tmp_path)
    j.reserve_unknown(path, policy(), job("public-news-01"))
    with pytest.raises(j.Stop, match="JOURNAL_BUDGET_OR_INTENT_STOP"):
        j.reserve_unknown(path, policy(), job("public-news-01"))
    assert len(j.snapshot(path)["items"]) == 1


def test_daily_and_total_caps_survive_restarts(tmp_path):
    path = directory(tmp_path)
    j.reserve_unknown(path, policy(), job("public-news-01"))
    j.reserve_unknown(path, policy(), job("public-news-02", cost=1))
    with pytest.raises(j.Stop, match="JOURNAL_BUDGET_OR_INTENT_STOP"):
        j.reserve_unknown(path, policy(), job("public-news-03", cost=1))
    j.reserve_unknown(path, policy(), job("public-news-03", day="2026-11-04", cost=2))
    with pytest.raises(j.Stop, match="JOURNAL_BUDGET_OR_INTENT_STOP"):
        j.reserve_unknown(path, policy(), job("public-news-04", day="2026-11-05", cost=1))


def test_private_and_unsafe_job_rejected_before_file_creation(tmp_path):
    path = directory(tmp_path)
    dangerous = job("public-news-01")
    dangerous["data_class"] = "PRIVATE"
    with pytest.raises(j.Stop, match="JOURNAL_BUDGET_OR_INTENT_STOP"):
        j.reserve_unknown(path, policy(), dangerous)
    assert list(path.iterdir()) == []


def test_file_symlink_and_hardlink_rejected(tmp_path):
    path = directory(tmp_path)
    outside = tmp_path / "victim"
    outside.write_text("untouched", encoding="utf8")
    link = path / "intent-public-news-01.json"
    link.symlink_to(outside)
    with pytest.raises(j.Stop, match="JOURNAL_INVALID_OR_IO_STOP"):
        j.snapshot(path)
    assert outside.read_text("utf8") == "untouched"
    link.unlink()
    (path / "intent-public-news-01.json").hardlink_to(outside)
    with pytest.raises(j.Stop, match="JOURNAL_FILE_CUSTODY_STOP"):
        j.snapshot(path)


def test_partial_or_corrupt_record_is_not_replayed(tmp_path):
    path = directory(tmp_path)
    name = path / "intent-public-news-01.json"
    name.write_text('{"intent_id":', encoding="utf8")
    name.chmod(0o600)
    with pytest.raises(j.Stop, match="JOURNAL_INVALID_OR_IO_STOP"):
        j.reserve_unknown(path, policy(), job("public-news-01"))


def test_no_unknown_entries_or_insecure_directory(tmp_path):
    path = directory(tmp_path)
    (path / "README.txt").write_text("unexpected", encoding="utf8")
    with pytest.raises(j.Stop, match="JOURNAL_UNEXPECTED_ENTRY_STOP"):
        j.snapshot(path)
    (path / "README.txt").unlink()
    path.chmod(0o755)
    with pytest.raises(j.Stop, match="JOURNAL_DIRECTORY_CUSTODY_STOP"):
        j.reserve_unknown(path, policy(), job("public-news-01"))


def test_nonblocking_lock_prevents_concurrent_budget_bypass(tmp_path):
    path = directory(tmp_path)
    a = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(a, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(j.Stop, match="JOURNAL_LOCKED_STOP"):
            j.reserve_unknown(path, policy(), job("public-news-01"))
    finally:
        os.close(a)
    assert j.snapshot(path)["items"] == []


def test_duplicate_json_keys_and_fake_accepted_receipt_denied(tmp_path):
    path = directory(tmp_path)
    j.reserve_unknown(path, policy(), job("public-news-01"))
    target = path / "intent-public-news-01.json"
    old = json.loads(target.read_text("utf8"))
    old["status"] = "SETTLED"
    target.write_text(json.dumps(old), encoding="utf8")
    with pytest.raises(j.Stop, match="JOURNAL_INVALID_OR_IO_STOP"):
        j.snapshot(path)
    target.write_text('{"intent_id":"public-news-01","intent_id":"public-news-01"}', encoding="utf8")
    with pytest.raises(j.Stop, match="JOURNAL_DUPLICATE_JSON_KEY_STOP"):
        j.snapshot(path)


def test_invalid_path_and_no_auto_creation(tmp_path):
    no = tmp_path / "not-a-directory"
    with pytest.raises(j.Stop, match="JOURNAL_DIRECTORY_IO_STOP"):
        j.reserve_unknown(no, policy(), job("public-news-01"))
    assert not no.exists()


def test_no_transport_signer_or_live_authority_imported(tmp_path):
    import ast
    source = Path(j.__file__).read_text("utf8")
    tree = ast.parse(source)
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                calls.append(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                calls.append(node.func.attr)
    for forbidden in ("urlopen", "post", "request", "connect", "sign",
                      "system", "Popen", "run", "unlink", "rmtree",
                      "remove", "rename"):
        assert forbidden not in calls
    assert not (tmp_path / "unrelated").exists()
