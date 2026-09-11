import json

import pytest

from flop_agent import core
from flop_agent import discord_knowledge as knowledge_app
from flop_agent import discord_tclk_review as discord_review
from flop_agent import tclk_review_evidence


NOW = 2_000_000_000_000


def _offer(index: int = 1, *, job_id: str = "job-safe-open") -> dict:
    return {
        "id": "0x" + f"{index:064x}",
        "frame_type": "offer",
        "role": "payer",
        "read_only": True,
        "accepted": False,
        "rail": "paper",
        "job_proto": "a2a",
        "job_id": job_id,
        "expires_ms": NOW + 900_000,
        "frame_sha256": f"{index:064x}",
        "terms_full": f"verification | full spec: /kv/tclk-job-en/{job_id}",
    }


def _resolved_record(item: dict, *, spec: str = "verification | answer from this note only") -> dict:
    return {
        "offer_id": item["id"],
        "job_id": item["job_id"],
        "frame_sha256": item["frame_sha256"],
        "expires_ms": item["expires_ms"],
        "resolved_at": "2033-05-18T03:33:20+00:00",
        "triage_reason": "human_review_required",
        "full_spec": {
            "namespace": "tclk-job-en",
            "key": item["job_id"],
            "value": spec,
            "sha256": __import__("hashlib").sha256(spec.encode()).hexdigest(),
            "bytes": len(spec.encode()),
        },
        "material": None,
        "external_url_present": False,
        "read_count": 1,
        "accepted": False,
    }


def test_capture_persists_hash_pinned_evidence_once_and_survives_offer_expiry(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)
    item = _offer()
    calls = []

    def reader(namespace: str, key: str) -> str:
        calls.append((namespace, key))
        return "verification | self-contained public note"

    first = tclk_review_evidence.capture(item, reader=reader, now_ms=NOW)
    assert calls == [("tclk-job-en", "job-safe-open")]
    assert first["accepted"] is False
    assert tclk_review_evidence.get(item["id"])["full_spec"]["sha256"] == first["full_spec"]["sha256"]

    def forbidden_reader(_namespace: str, _key: str) -> str:
        raise AssertionError("duplicate evidence must not re-read the network")

    second = tclk_review_evidence.capture(item, reader=forbidden_reader, now_ms=NOW + 1)
    assert second == first
    assert tclk_review_evidence.get(item["id"])["expires_ms"] < NOW + 10_000_000


def test_capture_fail_closed_does_not_create_evidence_on_read_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)

    def failed(_namespace: str, _key: str) -> str:
        raise TimeoutError("network details must stay private")

    with pytest.raises(tclk_review_evidence.EvidenceError, match="full_spec_read_failed"):
        tclk_review_evidence.capture(_offer(), reader=failed, now_ms=NOW)
    assert not tclk_review_evidence.evidence_path().exists()


def test_evidence_store_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)
    monkeypatch.setattr(tclk_review_evidence, "MAX_RECORDS", 3)
    for index in range(1, 5):
        tclk_review_evidence.capture(
            _offer(index),
            reader=lambda _namespace, _key: "verification | bounded public evidence",
            now_ms=NOW,
        )
    records = tclk_review_evidence.load_store()["records"]
    assert len(records) == 3
    assert [record["offer_id"] for record in records] == [_offer(i)["id"] for i in (2, 3, 4)]


def test_local_evidence_hash_tamper_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)
    item = _offer()
    tclk_review_evidence.capture(
        item,
        reader=lambda _namespace, _key: "verification | original public evidence",
        now_ms=NOW,
    )
    path = tclk_review_evidence.evidence_path()
    payload = json.loads(path.read_text("utf-8"))
    payload["records"][0]["full_spec"]["value"] = "tampered"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(tclk_review_evidence.EvidenceError, match="evidence_hash_mismatch"):
        tclk_review_evidence.load_store()


def test_new_candidate_auto_resolves_and_notice_requires_no_chatgpt_relay(monkeypatch):
    item = _offer()
    monkeypatch.setattr(discord_review.observer, "load_state", lambda: {"tclk": {"offers": {item["id"]: item}}})
    monkeypatch.setattr(knowledge_app, "_TCLK_NOTICE_BASELINED", True)
    monkeypatch.setattr(knowledge_app, "_TCLK_NOTICE_SEEN", set())
    monkeypatch.setattr(discord_review, "_AUTO_FAILURE_NOTIFIED", set())
    monkeypatch.setattr(discord_review.tclk_review_evidence, "capture", lambda _item: _resolved_record(item))

    notices = discord_review._new_auto_review_notices()
    assert len(notices) == 1
    assert "AUTO-RESOLVE: PASS" in notices[0]
    assert "ChatGPTへ貼る必要はありません" in notices[0]
    assert "/tclk " not in notices[0]
    assert item["id"] in knowledge_app._TCLK_NOTICE_SEEN
    assert len(notices[0]) <= 2000


def test_transient_auto_resolution_failure_retries_without_repeated_failure_spam(monkeypatch):
    item = _offer()
    monkeypatch.setattr(discord_review.observer, "load_state", lambda: {"tclk": {"offers": {item["id"]: item}}})
    monkeypatch.setattr(knowledge_app, "_TCLK_NOTICE_BASELINED", True)
    monkeypatch.setattr(knowledge_app, "_TCLK_NOTICE_SEEN", set())
    monkeypatch.setattr(discord_review, "_AUTO_FAILURE_NOTIFIED", set())

    def transient(_item):
        raise tclk_review_evidence.EvidenceError("full_spec_read_failed")

    monkeypatch.setattr(discord_review.tclk_review_evidence, "capture", transient)
    first = discord_review._new_auto_review_notices()
    second = discord_review._new_auto_review_notices()
    assert len(first) == 1 and "自動で再試行" in first[0]
    assert second == []
    assert item["id"] not in knowledge_app._TCLK_NOTICE_SEEN

    monkeypatch.setattr(discord_review.tclk_review_evidence, "capture", lambda _item: _resolved_record(item))
    third = discord_review._new_auto_review_notices()
    assert len(third) == 1 and "AUTO-RESOLVE: PASS" in third[0]
    assert item["id"] in knowledge_app._TCLK_NOTICE_SEEN


def test_stored_evidence_command_works_without_live_offer(monkeypatch):
    item = _offer()
    record = _resolved_record(item)
    monkeypatch.setattr(discord_review.tclk_review_evidence, "get", lambda offer_id: record if offer_id == item["id"] else None)
    control = discord_review.Control({"1"}, "2")
    result = control.command("1", f"/tclk-evidence {item['id']}", "2")
    assert result["ok"] is True
    assert "may be expired" in result["message"]
    assert record["full_spec"]["sha256"] in result["message"]
    assert "No sign, post, accept" in result["message"]
