import hashlib

from flop_agent import discord_knowledge as knowledge_app
from flop_agent import discord_tclk_review as discord_review
from flop_agent import tclk_review_evidence


EXPIRES_MS = 4_000_000_000_000


def _offer(index: int = 1, *, proto: str = "a2a") -> dict:
    job_id = f"job-restart-{index}"
    return {
        "id": "0x" + f"{index:064x}",
        "frame_type": "offer",
        "role": "payer",
        "read_only": True,
        "accepted": False,
        "rail": "paper",
        "job_proto": proto,
        "job_id": job_id,
        "expires_ms": EXPIRES_MS,
        "frame_sha256": f"{index:064x}",
        "terms_full": f"verification | full spec: /kv/tclk-job-en/{job_id}",
    }


def _record(item: dict) -> dict:
    spec = "verification | restart-safe public evidence"
    return {
        "offer_id": item["id"],
        "job_id": item["job_id"],
        "frame_sha256": item["frame_sha256"],
        "expires_ms": item["expires_ms"],
        "resolved_at": "2096-10-02T07:06:40+00:00",
        "triage_reason": "human_review_required",
        "full_spec": {
            "namespace": "tclk-job-en",
            "key": item["job_id"],
            "value": spec,
            "sha256": hashlib.sha256(spec.encode()).hexdigest(),
            "bytes": len(spec.encode()),
        },
        "material": None,
        "external_url_present": False,
        "read_count": 1,
        "accepted": False,
    }


def _startup(monkeypatch, item: dict) -> None:
    monkeypatch.setattr(
        discord_review.observer,
        "load_state",
        lambda: {"tclk": {"offers": {item["id"]: item}}},
    )
    monkeypatch.setattr(knowledge_app, "_TCLK_NOTICE_BASELINED", False)
    monkeypatch.setattr(knowledge_app, "_TCLK_NOTICE_SEEN", {"stale"})
    monkeypatch.setattr(discord_review, "_AUTO_FAILURE_NOTIFIED", {"stale"})


def test_restart_baseline_resolves_live_reviewable_candidate(monkeypatch):
    item = _offer()
    record = _record(item)
    calls = []
    _startup(monkeypatch, item)
    monkeypatch.setattr(
        discord_review.tclk_review_evidence,
        "load_store",
        lambda: {"schema_version": 1, "records": []},
    )

    def capture(candidate):
        calls.append(candidate["id"])
        return record

    monkeypatch.setattr(discord_review.tclk_review_evidence, "capture", capture)

    notices = discord_review._new_auto_review_notices()

    assert calls == [item["id"]]
    assert len(notices) == 1
    assert "AUTO-RESOLVE: PASS" in notices[0]
    assert knowledge_app._TCLK_NOTICE_BASELINED is True
    assert knowledge_app._TCLK_NOTICE_SEEN == {item["id"]}


def test_restart_baseline_does_not_reread_exact_durable_evidence(monkeypatch):
    item = _offer()
    record = _record(item)
    _startup(monkeypatch, item)
    monkeypatch.setattr(
        discord_review.tclk_review_evidence,
        "load_store",
        lambda: {"schema_version": 1, "records": [record]},
    )

    def forbidden_capture(_candidate):
        raise AssertionError("durable exact evidence must not be re-read on restart")

    monkeypatch.setattr(discord_review.tclk_review_evidence, "capture", forbidden_capture)

    notices = discord_review._new_auto_review_notices()

    assert notices == []
    assert knowledge_app._TCLK_NOTICE_BASELINED is True
    assert knowledge_app._TCLK_NOTICE_SEEN == {item["id"]}


def test_restart_baseline_still_suppresses_nonreviewable_offer(monkeypatch):
    item = _offer(proto="pin")
    _startup(monkeypatch, item)
    monkeypatch.setattr(
        discord_review.tclk_review_evidence,
        "load_store",
        lambda: {"schema_version": 1, "records": []},
    )

    def forbidden_capture(_candidate):
        raise AssertionError("non-reviewable startup offer must stay baselined")

    monkeypatch.setattr(discord_review.tclk_review_evidence, "capture", forbidden_capture)

    notices = discord_review._new_auto_review_notices()

    assert notices == []
    assert knowledge_app._TCLK_NOTICE_BASELINED is True
    assert knowledge_app._TCLK_NOTICE_SEEN == {item["id"]}


def test_restart_baseline_fails_closed_if_durable_store_is_unreadable(monkeypatch):
    item = _offer()
    _startup(monkeypatch, item)

    def unreadable():
        raise tclk_review_evidence.EvidenceError("evidence_store_unreadable")

    monkeypatch.setattr(discord_review.tclk_review_evidence, "load_store", unreadable)

    notices = discord_review._new_auto_review_notices()

    assert notices == []
    assert knowledge_app._TCLK_NOTICE_BASELINED is False
    assert knowledge_app._TCLK_NOTICE_SEEN == {"stale"}
