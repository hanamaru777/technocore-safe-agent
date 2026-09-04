"""Fail-closed eligibility overlay for source-backed onboarding topics.

Installed only by Resident/Discord processes.  The isolated Signer is deliberately
unchanged and continues to render the already-proven fixed templates.
"""
from __future__ import annotations

from . import autopilot, knowledge

SOURCE_BACKED_SIGNED_TOPICS = {
    "nonce",
    "did_signature",
    "technocore_api",
    "prompt_injection_safety",
    "repo_tests_bugs",
    "agent_use_case",
}

_INSTALLED = False
_ORIGINAL_ELIGIBLE = autopilot.eligible


def guarded_eligible(candidate: dict) -> tuple[bool, str, str | None]:
    allowed, reason, topic = _ORIGINAL_ELIGIBLE(candidate)
    if not allowed or topic not in SOURCE_BACKED_SIGNED_TOPICS:
        return allowed, reason, topic
    if not knowledge.signable_now(str(topic)):
        return False, "knowledge_source_stale_or_unverified", topic
    return allowed, reason, topic


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    # autopilot's facade propagates this assignment to policy/core modules whose
    # builders resolve `eligible` at runtime.
    autopilot.eligible = guarded_eligible
    _INSTALLED = True
