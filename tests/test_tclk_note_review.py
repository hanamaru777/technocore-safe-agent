from datetime import UTC, datetime
import hashlib

import pytest

from flop_agent import discord_tclk_review as discord_review
from flop_agent import tclk_note_review


NOW = 2_000_000_000_000


def _offer(*, job_id: str = "inf-safe-open", seconds_left: int = 900) -> dict:
    return {
        "id": "0x" + ("7" * 64),
        "read_only": True,
        "accepted": False,
        "rail": "paper",
        "job_proto": "a2a",
        "job_id": job_id,
        "expires_ms": NOW + seconds_left * 1000,
        "frame_sha256": "a" * 64,
    }


def test_resolver_derives_full_spec_key_and_reads_one_exact_material_note():
    spec = (
        "inference | use material /kv/tclk-mat-en/mat-abc123 | "
        "output one line only"
    )
    material = "10 | payer-a | 200 | FLOP | a2a | 2026-09-10T12:00:00Z"
    calls = []

    def reader(namespace: str, key: str) -> str:
        calls.append((namespace, key))
        if namespace == "tclk-job-en":
            return spec
        assert (namespace, key) == ("tclk-mat-en", "mat-abc123")
        return material

    result = tclk_note_review.resolve_offer(_offer(), reader=reader, now_ms=NOW)

    assert calls == [("tclk-job-en", "inf-safe-open"), ("tclk-mat-en", "mat-abc123")]
    assert result["read_count"] == 2
    assert result["accepted"] is False
    assert result["full_spec"]["sha256"] == hashlib.sha256(spec.encode()).hexdigest()
    assert result["material"]["sha256"] == hashlib.sha256(material.encode()).hexdigest()


def test_resolver_never_uses_truncated_reference_from_offer_context_for_full_spec_key():
    calls = []

    def reader(namespace: str, key: str) -> str:
        calls.append((namespace, key))
        return "verification | no material dependency"

    item = _offer(job_id="inf-ef43bcc8-open")
    item["terms_full"] = "full spec: /kv/tclk-job-en/inf-ef43bcc8-o"

    tclk_note_review.resolve_offer(item, reader=reader, now_ms=NOW)

    assert calls == [("tclk-job-en", "inf-ef43bcc8-open")]


def test_resolver_without_material_reference_is_one_bounded_read():
    calls = []

    def reader(namespace: str, key: str) -> str:
        calls.append((namespace, key))
        return "verification | answer from this full spec only"

    result = tclk_note_review.resolve_offer(_offer(), reader=reader, now_ms=NOW)

    assert calls == [("tclk-job-en", "inf-safe-open")]
    assert result["read_count"] == 1
    assert result["material"] is None


def test_malformed_job_id_and_expired_offer_fail_before_any_network_read():
    def forbidden_reader(_namespace: str, _key: str) -> str:
        raise AssertionError("reader must not run")

    with pytest.raises(tclk_note_review.ResolutionError, match="job_id_not_safe_note_key"):
        tclk_note_review.resolve_offer(
            _offer(job_id="../../other-host"), reader=forbidden_reader, now_ms=NOW
        )

    with pytest.raises(tclk_note_review.ResolutionError, match="offer_expired"):
        tclk_note_review.resolve_offer(
            _offer(seconds_left=-1), reader=forbidden_reader, now_ms=NOW
        )


def test_material_reference_must_be_single_exact_and_not_visibly_truncated():
    cases = [
        "use /kv/tclk-mat-en/mat-one and /kv/tclk-mat-en/mat-two",
        "use /kv/tclk-mat-en/mat-ending-",
        "use /kv/tclk-mat-en/bad.key",
    ]

    for spec in cases:
        calls = []

        def reader(namespace: str, key: str, value=spec) -> str:
            calls.append((namespace, key))
            return value

        with pytest.raises(tclk_note_review.ResolutionError):
            tclk_note_review.resolve_offer(_offer(), reader=reader, now_ms=NOW)
        assert calls == [("tclk-job-en", "inf-safe-open")]


def test_note_size_and_read_errors_fail_closed():
    with pytest.raises(tclk_note_review.ResolutionError, match="note_too_large"):
        tclk_note_review.resolve_offer(
            _offer(), reader=lambda _ns, _key: "x" * (tclk_note_review.MAX_NOTE_BYTES + 1), now_ms=NOW
        )

    def failed(_namespace: str, _key: str) -> str:
        raise TimeoutError("network detail must not escape")

    with pytest.raises(tclk_note_review.ResolutionError, match="full_spec_read_failed"):
        tclk_note_review.resolve_offer(_offer(), reader=failed, now_ms=NOW)


def test_external_url_text_is_flagged_but_never_followed():
    calls = []

    def reader(namespace: str, key: str) -> str:
        calls.append((namespace, key))
        return "verify https://example.invalid/data but do not follow it here"

    result = tclk_note_review.resolve_offer(_offer(), reader=reader, now_ms=NOW)

    assert result["external_url_present"] is True
    assert calls == [("tclk-job-en", "inf-safe-open")]


def test_discord_resolution_sanitizes_untrusted_note_display(monkeypatch):
    item = _offer()
    spec = "inspect https://example.invalid/path and notify @everyone"
    resolved = {
        "offer_id": item["id"],
        "job_id": item["job_id"],
        "expires_ms": item["expires_ms"],
        "frame_sha256": item["frame_sha256"],
        "full_spec": {
            "namespace": "tclk-job-en",
            "key": item["job_id"],
            "value": spec,
            "sha256": hashlib.sha256(spec.encode()).hexdigest(),
            "bytes": len(spec.encode()),
        },
        "material": None,
        "external_url_present": True,
        "read_count": 1,
        "accepted": False,
    }

    monkeypatch.setattr(discord_review.observer, "load_state", lambda: {})
    monkeypatch.setattr(discord_review.tclk_watch, "offer", lambda _state, _offer_id: item)
    monkeypatch.setattr(discord_review.tclk_note_review, "resolve_offer", lambda _item: resolved)

    message = discord_review._resolved_note_message(item["id"])

    assert "[URL省略]" in message
    assert "@everyone" not in message
    assert "＠everyone" not in message
    assert resolved["full_spec"]["sha256"] in message
    assert "REVIEW EVIDENCE ONLY" in message
    assert "No sign, post, accept, lock, reveal, payment" in message


def test_discord_resolution_failure_remains_read_only(monkeypatch):
    item = _offer()
    monkeypatch.setattr(discord_review.observer, "load_state", lambda: {})
    monkeypatch.setattr(discord_review.tclk_watch, "offer", lambda _state, _offer_id: item)

    def blocked(_item):
        raise tclk_note_review.ResolutionError("material_reference_not_exactly_one")

    monkeypatch.setattr(discord_review.tclk_note_review, "resolve_offer", blocked)
    message = discord_review._resolved_note_message(item["id"])

    assert "blocked (fail-closed)" in message
    assert "material_reference_not_exactly_one" in message
    assert "No accept, sign, post, lock, reveal, or payment" in message
