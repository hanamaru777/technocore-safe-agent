from datetime import UTC, datetime
from pathlib import Path

from flop_agent import discord_tclk_review as review


def _offer(offer_id: str = "0x" + ("b" * 64), *, seconds_left: int = 900) -> dict:
    now_ms = int(datetime.now(UTC).timestamp() * 1000)
    terms = "verification | count rows in a retained public tclk board excerpt"
    return {
        "id": offer_id,
        "counterpart_fingerprint": "abcdef1234567890",
        "frame_type": "offer",
        "role": "payer",
        "job_proto": "a2a",
        "job_id": "stored-review",
        "amount": "200",
        "asset": "FLOP",
        "rail": "paper",
        "expires_ms": now_ms + (seconds_left * 1000),
        "terms": terms[:280],
        "terms_full": terms,
        "frame_sha256": "c" * 64,
        "read_only": True,
        "accepted": False,
    }


def _state(item: dict) -> dict:
    return {"tclk": {"offers": {item["id"]: item}}}


def _runtime_probe_must_not_run():
    raise AssertionError("stored review must not re-probe the live parser")


def test_best_review_uses_retained_validated_offer_without_runtime_probe(monkeypatch):
    item = _offer()
    monkeypatch.setattr(review.observer, "load_state", lambda: _state(item))
    monkeypatch.setattr(review.tclk_watch, "runtime_status", _runtime_probe_must_not_run)

    message = review._stored_best_message()

    assert item["id"] in message
    assert "human_review_required" in message
    assert "candidate判定はaccept承認ではありません" in message
    assert "does not re-probe the live bridge" in message
    assert "did not accept, sign, post, lock, reveal, or pay" in message


def test_detail_review_uses_retained_full_evidence_without_runtime_probe(monkeypatch):
    item = _offer("0x" + ("d" * 64))
    monkeypatch.setattr(review.observer, "load_state", lambda: _state(item))
    monkeypatch.setattr(review.tclk_watch, "runtime_status", _runtime_probe_must_not_run)

    message = review._stored_detail_message(item["id"])

    assert "=== FULL TERMS" in message
    assert item["terms_full"] in message
    assert item["frame_sha256"] in message
    assert "retained at ingestion" in message


def test_opportunity_list_uses_local_state_without_runtime_probe(monkeypatch):
    item = _offer("0x" + ("e" * 64))
    monkeypatch.setattr(review.observer, "load_state", lambda: _state(item))
    monkeypatch.setattr(review.tclk_watch, "runtime_status", _runtime_probe_must_not_run)

    message = review._stored_opportunities_message()

    assert item["id"] in message
    assert "validated offers: 1" in message
    assert "Nothing was accepted" not in message
    assert "does not re-probe the live bridge" in message


def test_expired_offer_is_not_reintroduced_by_stored_review(monkeypatch):
    item = _offer("0x" + ("f" * 64), seconds_left=-1)
    monkeypatch.setattr(review.observer, "load_state", lambda: _state(item))
    monkeypatch.setattr(review.tclk_watch, "runtime_status", _runtime_probe_must_not_run)

    message = review._stored_best_message()

    assert item["id"] not in message
    assert "acceptしない" in message


def test_install_patches_only_discord_presentation_callbacks(monkeypatch):
    monkeypatch.setattr(review.app.base.base, "tclk_opportunities_message", lambda: "old-list")
    monkeypatch.setattr(review.app.base.base, "tclk_offer_message", lambda _id: "old-detail")
    monkeypatch.setattr(review.app, "_tclk_detail_message", lambda _id: "old-full")
    monkeypatch.setattr(review.app, "_tclk_best_message", lambda: "old-best")

    review.install()

    assert review.app.base.base.tclk_opportunities_message is review._stored_opportunities_message
    assert review.app.base.base.tclk_offer_message is review._stored_offer_message
    assert review.app._tclk_detail_message is review._stored_detail_message
    assert review.app._tclk_best_message is review._stored_best_message


def test_oracle_discord_service_uses_stored_review_entrypoint():
    unit = Path("packaging/oracle/discord.service").read_text("utf-8")
    approval = Path("src/flop_agent/discord_tclk_approval.py").read_text("utf-8")
    stored_review = Path("src/flop_agent/discord_tclk_review.py").read_text("utf-8")
    assert "ExecStart=/opt/technocore-safe-agent/.venv/bin/python -m flop_agent.discord_tclk_approval" in unit
    assert "from . import discord_tclk_review as app" in approval
    assert "from . import discord_knowledge as app" in stored_review
