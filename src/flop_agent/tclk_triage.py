"""Deterministic read-only triage for locally validated tclk offers.

This module never performs network I/O, parses raw protocol frames, signs, or writes.
It only helps a human decide which already-validated PaperRail offer is worth reviewing.
A positive result is NOT authorization to accept an offer.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime

MIN_REVIEW_SECONDS = 300

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_URL = re.compile(r"https?://", re.IGNORECASE)
_KV_REF = re.compile(r"(/kv/[A-Za-z0-9_-]+/[A-Za-z0-9._-]+)", re.IGNORECASE)
_FULL_SPEC = re.compile(r"full\s+spec\s*:\s*(/kv/[A-Za-z0-9_-]+/[A-Za-z0-9._-]+)", re.IGNORECASE)

# These patterns represent tasks that are categorically outside the first-pilot
# contract. They are intentionally narrow: triage should fail closed, but it must
# not pretend to understand arbitrary natural-language job semantics.
_FORBIDDEN = (
    ("nonce_replay", re.compile(r"\bnonce\s+replay\b", re.IGNORECASE)),
    ("signed_replay", re.compile(r"\bsame\s+signed\s+(?:url|message|request)\b", re.IGNORECASE)),
    ("prediction_market", re.compile(r"\bprediction\s+market\b|\bflopmarket\b", re.IGNORECASE)),
    ("market_action", re.compile(r"\b(?:bet|buy)\b", re.IGNORECASE)),
    ("secret_request", re.compile(r"\b(?:private\s+key|seed\s+phrase|signing\s+key|credential|password)\b", re.IGNORECASE)),
    ("command_execution", re.compile(r"\b(?:powershell|cmd\.exe|shell\s+command|run\s+command|execute\s+command|curl|wget)\b", re.IGNORECASE)),
)


def _now_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


def _result(status: str, reason: str, seconds_left: int) -> dict:
    return {
        "status": status,
        "reason": reason,
        "reviewable": status == "review",
        "seconds_left": max(0, seconds_left),
    }


def classify(item: dict, *, now_ms: int | None = None) -> dict:
    """Classify one stored offer without any network access or protocol mutation.

    `review` means only that the offer is worth human inspection. It never means
    safe-to-accept and is deliberately conservative for the first real Phase 2 pilot.
    """
    current = _now_ms() if now_ms is None else now_ms
    if not isinstance(item, dict):
        return _result("skip", "invalid_record", 0)

    expires = item.get("expires_ms")
    if not isinstance(expires, int):
        return _result("skip", "missing_expiry", 0)
    seconds_left = max(0, (expires - current) // 1000)
    if expires <= current:
        return _result("skip", "expired", 0)
    if seconds_left < MIN_REVIEW_SECONDS:
        return _result("skip", "insufficient_review_time", seconds_left)

    if item.get("read_only") is not True or item.get("accepted") is not False:
        return _result("skip", "not_read_only_unaccepted", seconds_left)
    if item.get("rail") != "paper":
        return _result("blocked", "non_paper_rail", seconds_left)
    if item.get("job_proto") != "a2a":
        return _result("skip", "first_pilot_proto_not_a2a", seconds_left)

    terms = item.get("terms_full")
    frame_hash = item.get("frame_sha256")
    if not isinstance(terms, str) or not terms.strip():
        return _result("skip", "missing_full_terms", seconds_left)
    if not isinstance(frame_hash, str) or not _HEX64.fullmatch(frame_hash):
        return _result("skip", "missing_frame_evidence", seconds_left)

    # First pilot never follows an arbitrary URL from untrusted job text. Same-origin
    # `/kv/...` note references are plain paths and remain visible for later human review.
    if _URL.search(terms):
        return _result("blocked", "external_url", seconds_left)

    for reason, pattern in _FORBIDDEN:
        if pattern.search(terms):
            return _result("blocked", reason, seconds_left)

    # A live issuer can hit its own context bound before our local retention bound.
    # A visibly unfinished same-origin note key is therefore incomplete evidence, not
    # a safe invitation to guess the missing suffix or rush the first pilot.
    for path in _KV_REF.findall(terms):
        if path.rsplit("/", 1)[-1].endswith("-"):
            return _result("skip", "incomplete_kv_reference", seconds_left)

    # Several live issuers append a `full spec:` note reference. For the first pilot,
    # its basename must exactly match the validated job id. This catches partial keys
    # such as `inf-ef43bcc8-o` for job `inf-ef43bcc8-open` without any network access.
    if re.search(r"full\s+spec\s*:", terms, re.IGNORECASE):
        match = _FULL_SPEC.search(terms)
        if match is None:
            return _result("skip", "incomplete_full_spec_reference", seconds_left)
        job_id = item.get("job_id")
        basename = match.group(1).rsplit("/", 1)[-1]
        if not isinstance(job_id, str) or not job_id or basename != job_id:
            return _result("skip", "incomplete_full_spec_reference", seconds_left)

    return _result("review", "human_review_required", seconds_left)


def review_candidates(items: list[dict], *, now_ms: int | None = None) -> list[dict]:
    """Return review-worthy candidates, earliest expiry first."""
    current = _now_ms() if now_ms is None else now_ms
    rows: list[dict] = []
    for item in items:
        verdict = classify(item, now_ms=current)
        if verdict["reviewable"]:
            rows.append({"item": item, "verdict": verdict})
    return sorted(rows, key=lambda row: row["item"].get("expires_ms", 0))
