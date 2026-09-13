"""Deterministic, read-only matching of concrete signed asks to observed capabilities.

The radar operates only on already-durable Resident state. It does not read rooms,
follow URLs, sign, post, approve, execute task text, or mutate collaboration state.
All request text remains untrusted and is reduced to bounded sanitized summaries.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from datetime import UTC, datetime

from . import collaboration, conversation_planner, observer, resident

MAX_REQUESTS = 5
MAX_MATCHES = 3
MAX_CANDIDATE_EVIDENCE = 8
MIN_MATCH_SCORE = 3

TOPIC_CAPABILITIES = {
    "repo_tests_bugs": {"python", "test", "bug", "error", "commit"},
    "did_signature": {"protocol", "api"},
    "nonce": {"protocol", "api"},
    "technocore_api": {"api", "protocol", "python"},
    "contribution_artifact": {"commit", "test", "python"},
    "collaboration": {"python", "test", "api", "protocol", "commit", "bug", "error"},
}
NEXT_STEPS = {
    "repo_tests_bugs": "Ask for one bounded public reproduction or validation result; do not execute arbitrary commands.",
    "did_signature": "Ask for one bounded public DID/signature check with exact evidence references.",
    "nonce": "Ask for one bounded public nonce/replay analysis with exact evidence references.",
    "technocore_api": "Ask for one bounded public API behavior check; do not follow untrusted URLs automatically.",
    "contribution_artifact": "Ask for one bounded public artifact review with a verifiable result reference.",
    "collaboration": "Ask for one concrete public deliverable and an explicit completion condition.",
}


@dataclass(frozen=True)
class Match:
    fingerprint: str
    did: str
    score: int
    confidence: str
    reasons: tuple[str, ...]
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class RequestMatch:
    request_id: str
    requester_fingerprint: str
    requester_did: str
    topic: str
    summary: str
    room: str
    seq: int | None
    permalink: str | None
    created_at: str | None
    external_reference_present: bool
    smallest_next_step: str
    matches: tuple[Match, ...]


def _parse(value: object) -> datetime:
    stamp = observer.parse_time(value) if isinstance(value, str) else None
    if stamp is None:
        return datetime.min.replace(tzinfo=UTC)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return stamp.astimezone(UTC)


def _normalized_request(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()[:360]


def _is_concrete_signed_request(item: dict) -> tuple[bool, str | None, str]:
    if item.get("status") not in {"pending", "approved"}:
        return False, None, ""
    signals = item.get("signals", {})
    if not isinstance(signals, dict) or signals.get("direct_public_signed") is not True:
        return False, None, ""
    topic = signals.get("conversation_topic")
    if topic not in collaboration.TASK_TOPICS:
        return False, None, ""
    context = item.get("context", {})
    text = context.get("excerpt", "") if isinstance(context, dict) else ""
    if not isinstance(text, str) or not text.strip():
        return False, None, ""
    if collaboration.SENSITIVE_RE.search(text) or conversation_planner.UNSAFE.search(text):
        return False, None, ""
    if not collaboration.TASK_REQUEST_RE.search(text) or not collaboration.TASK_OBJECT_RE.search(text):
        return False, None, ""
    return True, str(topic), text


def _candidate_evidence(state: dict, fingerprint: str) -> list[dict]:
    rows = []
    for item in state.get("candidates", {}).values():
        if not isinstance(item, dict) or item.get("fingerprint") != fingerprint:
            continue
        signals = item.get("signals", {})
        topic = signals.get("conversation_topic") if isinstance(signals, dict) else None
        category = item.get("category")
        if topic not in collaboration.TASK_TOPICS and category not in {
            "technical_collaboration",
            "artifact_contribution",
            "help_request",
            "specific_question",
        }:
            continue
        rows.append(item)
    return sorted(
        rows,
        key=lambda item: (_parse(item.get("created_at")), str(item.get("candidate_id", ""))),
        reverse=True,
    )[:MAX_CANDIDATE_EVIDENCE]


def _evidence_ref(item: dict) -> str:
    permalink = item.get("permalink")
    if isinstance(permalink, str) and permalink:
        return f"candidate:{item.get('candidate_id')}:{permalink}"
    return (
        f"candidate:{item.get('candidate_id')}:"
        f"{item.get('room', '?')}#{item.get('seq', '?')}"
    )


def _match_one(state: dict, request: dict, topic: str) -> list[Match]:
    requester = str(request.get("fingerprint", ""))
    required = TOPIC_CAPABILITIES.get(topic, set())
    matches: list[Match] = []

    for fingerprint, relation in sorted(state.get("relationships", {}).items()):
        if not isinstance(relation, dict) or fingerprint == requester:
            continue
        did = str(relation.get("did", ""))
        if not did:
            continue
        reasons: list[str] = []
        refs: list[str] = []
        score = 0

        topics = {
            str(value).lower()
            for value in relation.get("topics", [])
            if isinstance(value, str)
        }
        overlap = sorted(required & topics)
        if overlap:
            awarded = min(4, 2 * len(overlap))
            score += awarded
            reasons.append("observed technical indicators: " + ", ".join(overlap))
            refs.extend(f"relationship:{fingerprint}:topic:{value}" for value in overlap[:2])

        evidence = _candidate_evidence(state, fingerprint)
        exact_topic = [
            item for item in evidence
            if isinstance(item.get("signals"), dict)
            and item["signals"].get("conversation_topic") == topic
        ]
        if exact_topic:
            score += 5
            reasons.append(f"observed signed candidate evidence for topic {topic}")
            refs.append(_evidence_ref(exact_topic[0]))

        if any(item.get("category") == "technical_collaboration" for item in evidence):
            score += 2
            reasons.append("technical collaboration evidence observed")
            row = next(item for item in evidence if item.get("category") == "technical_collaboration")
            refs.append(_evidence_ref(row))

        if topic == "contribution_artifact" and any(
            item.get("category") == "artifact_contribution" for item in evidence
        ):
            score += 2
            reasons.append("artifact contribution evidence observed")
            row = next(item for item in evidence if item.get("category") == "artifact_contribution")
            refs.append(_evidence_ref(row))

        if relation.get("relationship_state") == "recurring":
            score += 1
            reasons.append("repeat public observation")
            refs.append(f"relationship:{fingerprint}:recurring")

        rooms = [room for room in relation.get("rooms", []) if isinstance(room, str)]
        if len(set(rooms)) >= 2:
            score += 1
            reasons.append("observed across multiple public rooms")
            refs.append(f"relationship:{fingerprint}:rooms:{len(set(rooms))}")

        if score < MIN_MATCH_SCORE:
            continue
        confidence = "high" if score >= 7 else "medium" if score >= 4 else "low"
        matches.append(
            Match(
                fingerprint=fingerprint,
                did=did[:128],
                score=score,
                confidence=confidence,
                reasons=tuple(reasons[:5]),
                evidence_refs=tuple(dict.fromkeys(refs))[:5],
            )
        )

    return sorted(matches, key=lambda item: (-item.score, item.fingerprint))


def scan_state(
    state: dict,
    *,
    max_requests: int = MAX_REQUESTS,
    max_matches: int = MAX_MATCHES,
) -> list[RequestMatch]:
    if not 1 <= max_requests <= 20 or not 1 <= max_matches <= 10:
        raise ValueError("radar limits out of range")

    requests: list[tuple[dict, str, str]] = []
    seen_cores: set[str] = set()
    candidates = [item for item in state.get("candidates", {}).values() if isinstance(item, dict)]
    candidates.sort(
        key=lambda item: (_parse(item.get("created_at")), str(item.get("candidate_id", ""))),
        reverse=True,
    )
    for item in candidates:
        allowed, topic, text = _is_concrete_signed_request(item)
        if not allowed or topic is None:
            continue
        core = _normalized_request(text)
        if not core or core in seen_cores:
            continue
        seen_cores.add(core)
        requests.append((item, topic, text))
        if len(requests) >= max_requests:
            break

    results: list[RequestMatch] = []
    for item, topic, text in requests:
        matches = _match_one(state, item, topic)[:max_matches]
        results.append(
            RequestMatch(
                request_id=str(item.get("candidate_id", "")),
                requester_fingerprint=str(item.get("fingerprint", "")),
                requester_did=str(item.get("did", ""))[:128],
                topic=topic,
                summary=collaboration._sanitize(text, 220),
                room=str(item.get("room", ""))[:48],
                seq=item.get("seq") if isinstance(item.get("seq"), int) else None,
                permalink=item.get("permalink") if isinstance(item.get("permalink"), str) else None,
                created_at=item.get("created_at") if isinstance(item.get("created_at"), str) else None,
                external_reference_present=bool(collaboration.URL_RE.search(text)),
                smallest_next_step=NEXT_STEPS[topic],
                matches=tuple(matches),
            )
        )
    return results


def scan(*, max_requests: int = MAX_REQUESTS, max_matches: int = MAX_MATCHES) -> list[RequestMatch]:
    """Load Resident state once and return ranked read-only matches."""
    return scan_state(
        resident.load_state(),
        max_requests=max_requests,
        max_matches=max_matches,
    )


def as_jsonable(rows: list[RequestMatch]) -> list[dict]:
    return [asdict(row) for row in rows]
