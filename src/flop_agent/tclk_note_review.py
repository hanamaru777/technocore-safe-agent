"""Human-triggered, read-only resolver for fixed-origin tclk Note evidence.

This module never posts, signs, accepts, locks, reveals, pays, executes shell text,
or follows arbitrary URLs. It derives the full-spec Note key only from the already
validated stored tclk job id, then optionally resolves one exact material Note
reference from that full spec. Returned SHA-256 values pin the exact evidence a
human reviewed; they are not proof that a world-writable Note is immutable.
"""
from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Callable

from . import core

FULL_SPEC_NAMESPACE = "tclk-job-en"
MATERIAL_NAMESPACE = "tclk-mat-en"
MAX_NOTE_BYTES = 8192

_KEY = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_OFFER_ID = re.compile(r"^0x[0-9a-f]{64}$")
_MATERIAL_REF = re.compile(
    r"(?<![A-Za-z0-9:/])/kv/tclk-mat-en/([a-z0-9][a-z0-9_-]{0,47})(?=$|[\s|,;:)\]}.])"
)
_EXTERNAL_URL = re.compile(r"https?://", re.IGNORECASE)


class ResolutionError(RuntimeError):
    """Fail-closed resolver error with a stable public-safe reason."""


def _now_ms() -> int:
    return int(datetime.now(UTC).timestamp() * 1000)


def _validate_offer(item: dict, *, now_ms: int) -> str:
    if not isinstance(item, dict):
        raise ResolutionError("invalid_offer")
    offer_id = item.get("id")
    if not isinstance(offer_id, str) or not _OFFER_ID.fullmatch(offer_id):
        raise ResolutionError("invalid_offer_id")
    if item.get("frame_type") not in {None, "offer"}:
        raise ResolutionError("invalid_frame_type")
    if item.get("read_only") is not True or item.get("accepted") is not False:
        raise ResolutionError("offer_not_read_only_unaccepted")
    if item.get("rail") != "paper":
        raise ResolutionError("non_paper_rail")
    if item.get("job_proto") != "a2a":
        raise ResolutionError("first_pilot_proto_not_a2a")
    expires = item.get("expires_ms")
    if not isinstance(expires, int) or expires <= now_ms:
        raise ResolutionError("offer_expired")
    frame_hash = item.get("frame_sha256")
    if not isinstance(frame_hash, str) or not _HEX64.fullmatch(frame_hash):
        raise ResolutionError("missing_frame_evidence")
    job_id = item.get("job_id")
    if not isinstance(job_id, str) or not _KEY.fullmatch(job_id):
        raise ResolutionError("job_id_not_safe_note_key")
    return job_id


def _read_bounded(
    namespace: str,
    key: str,
    *,
    reader: Callable[[str, str], str],
    failure_reason: str,
) -> dict:
    try:
        value = reader(namespace, key)
    except Exception as error:
        raise ResolutionError(failure_reason) from error
    if not isinstance(value, str) or not value:
        raise ResolutionError(failure_reason)
    encoded = value.encode("utf-8")
    if len(encoded) > MAX_NOTE_BYTES:
        raise ResolutionError("note_too_large")
    return {
        "namespace": namespace,
        "key": key,
        "value": value,
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "bytes": len(encoded),
    }


def _material_key(full_spec: str) -> str | None:
    material_prefix = f"/kv/{MATERIAL_NAMESPACE}/"
    prefix_count = full_spec.count(material_prefix)
    # The resolved full spec may describe external URLs as text, but it must not
    # redirect this resolver into another Note namespace. Any other /kv dependency
    # means we cannot claim to have complete bounded evidence.
    if full_spec.count("/kv/") != prefix_count:
        raise ResolutionError("unsupported_note_reference")
    matches = _MATERIAL_REF.findall(full_spec)
    if prefix_count == 0:
        return None
    # Any malformed, URL-embedded, query-suffixed, or otherwise partial occurrence is
    # outside the bounded first-pilot resolver contract. Do not guess or partially match.
    if prefix_count != len(matches):
        raise ResolutionError("material_reference_not_exact")
    unique = set(matches)
    if len(unique) != 1:
        raise ResolutionError("multiple_material_dependencies")
    key = next(iter(unique))
    if key.endswith("-") or not _KEY.fullmatch(key):
        raise ResolutionError("material_reference_incomplete")
    return key


def resolve_offer(
    item: dict,
    *,
    reader: Callable[[str, str], str] = core.read_note,
    now_ms: int | None = None,
) -> dict:
    """Resolve at most two fixed-origin Notes for one retained live offer.

    Read 1 is always ``tclk-job-en/<validated job_id>``. Read 2 occurs only when
    that exact full-spec Note itself contains an exact ``tclk-mat-en/<key>`` ref.
    Repeated references to the same material key still cause only one read. No other
    path, host, redirect target, command, or instruction is followed.
    """
    current = _now_ms() if now_ms is None else now_ms
    job_id = _validate_offer(item, now_ms=current)

    full_spec = _read_bounded(
        FULL_SPEC_NAMESPACE,
        job_id,
        reader=reader,
        failure_reason="full_spec_read_failed",
    )
    material_key = _material_key(full_spec["value"])
    material = None
    if material_key is not None:
        material = _read_bounded(
            MATERIAL_NAMESPACE,
            material_key,
            reader=reader,
            failure_reason="material_read_failed",
        )

    return {
        "offer_id": item["id"],
        "job_id": job_id,
        "expires_ms": item["expires_ms"],
        "frame_sha256": item["frame_sha256"],
        "full_spec": full_spec,
        "material": material,
        "external_url_present": bool(_EXTERNAL_URL.search(full_spec["value"])),
        "read_count": 1 + (1 if material is not None else 0),
        "accepted": False,
    }
