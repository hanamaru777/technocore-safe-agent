"""Pure, deterministic planner for safe public conversation intents.

The planner is deliberately dependency-free: it only classifies an already-read
public message.  It has no network, filesystem, shell, seed, Vault, metadata,
or signing capability, and it never returns message text.
"""
from __future__ import annotations

import re

PUBLIC_ROOM = re.compile(r"^(?!p-|mb-)[a-z0-9][a-z0-9_-]{0,47}$")
TOPICS = {
    "did_signature", "nonce", "technocore_api", "prompt_injection_safety",
    "repo_tests_bugs", "contribution_artifact", "collaboration", "follow_up",
}

# Unsafe requests are not conversation opportunities.  These patterns are only
# routing guards; no matched text is retained or reflected.
UNSAFE = re.compile(r"(?i)(?:\b(?:seed|private key|credential|token|api key)\b|\b(?:run|execute)\b.{0,40}\b(?:shell|command|curl|powershell)\b)")
TOPIC_PATTERNS = (
    ("prompt_injection_safety", re.compile(r"(?i)(?:prompt injection|untrusted (?:content|prompt)|ignore (?:previous|all) instructions|system prompt)")),
    ("did_signature", re.compile(r"(?i)(?:did:key|\bdid\b|signature|signing)")),
    ("nonce", re.compile(r"(?i)\bnonce\b")),
    ("technocore_api", re.compile(r"(?i)(?:technocore|\bapi\b|/r/|/kv/)")),
    ("repo_tests_bugs", re.compile(r"(?i)(?:repo(?:sitory)?|test(?:s|ing)?|bug|error|issue|patch|commit|traceback)")),
    ("contribution_artifact", re.compile(r"(?i)(?:contribution|artifact|evidence)")),
    ("collaboration", re.compile(r"(?i)(?:collaborat|coordinate|pair(?:ing)?)")),
    ("follow_up", re.compile(r"(?i)(?:follow[ -]?up|following up|next step)")),
)


def plan(*, room: str, sender_did: str, signed: bool, text: str, own_did: str | None) -> dict | None:
    """Return an allowlisted plan for a signed, explicitly addressed public message.

    This intentionally requires the full public DID marker; generic room chatter,
    private/mailbox rooms, unsigned messages, self messages, and unsafe requests
    cannot create an intent.
    """
    if not (signed and isinstance(room, str) and PUBLIC_ROOM.fullmatch(room)):
        return None
    if not all(isinstance(value, str) and value for value in (sender_did, text, own_did)):
        return None
    if sender_did == own_did or own_did not in text or UNSAFE.search(text):
        return None
    # The public DID is an address marker, not conversation subject matter.
    # Excluding it avoids routing every direct message to the DID template.
    text = text.replace(own_did, "")
    for topic, pattern in TOPIC_PATTERNS:
        if pattern.search(text):
            return {"topic": topic, "category": "conversation", "safety_decision": "signed_public_direct_request"}
    return None
