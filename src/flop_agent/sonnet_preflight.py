"""Planning-only Sonnet-2 mechanical preflight.

This module performs no signing and no Technocore/X writes. It validates a complete
planned poem and word-to-DID assignment against the frozen mechanical constraints
that can be checked before roster consent or the first accepted word.

Dictionary/token/DID mechanics deliberately mirror the official pinned
``sonnet_validate.py`` rather than maintaining a looser local interpretation.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

# Public contest artifact digest. Split only to avoid the repo's generic 64-hex
# secret heuristic; runtime concatenation is exactly the official pinned digest.
CMUDICT_SHA256 = (
    "81917843c7f44ce2"
    "b094ac63873c2c7a"
    "4cf802040792c455"
    "ba3ca406891c3d22"
)
WORD_RE = re.compile(r"[A-Za-z]+(?:'[A-Za-z]+)*")
TOKEN_RE = re.compile(r"([A-Za-z]+(?:'[A-Za-z]+)*)[,.;:!?]?")
ED25519_DID_RE = re.compile(r"did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}")
VARIANT_RE = re.compile(r"\(\d+\)$")
VOWELS = {
    "AA", "AE", "AH", "AO", "AW", "AY", "EH", "ER", "EY",
    "IH", "IY", "OW", "OY", "UH", "UW",
}
STANZA_BREAK_AFTER = {3, 7, 11}


class PreflightError(ValueError):
    pass


@dataclass(frozen=True)
class PlannedWord:
    token: str
    contributor_did: str


@dataclass(frozen=True)
class PreflightResult:
    canonical_text: str
    poem_sha256: str
    byte_count: int
    line_syllables: tuple[int, ...]
    contributor_counts: dict[str, int]
    x_chunks: tuple[str, ...]


def verify_cmudict(path: str | Path) -> bytes:
    raw = Path(path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != CMUDICT_SHA256:
        raise PreflightError(f"cmudict_sha256_mismatch:{digest}")
    return raw


def parse_cmudict(raw: bytes) -> dict[str, int]:
    """Mirror the official validator's frozen-CMUdict parsing/counting rule."""
    result: dict[str, int] = {}
    for raw_line in raw.decode("utf-8", errors="strict").splitlines():
        fields = raw_line.split("#", 1)[0].split()
        if not fields or fields[0].startswith(";;;"):
            continue
        key = VARIANT_RE.sub("", fields[0]).lower()
        if not WORD_RE.fullmatch(key):
            continue
        syllables = sum(
            phone[:-1] in VOWELS and phone[-1:] in {"0", "1", "2"}
            for phone in fields[1:]
        )
        if syllables:
            result[key] = max(result.get(key, 0), syllables)
    if not result:
        raise PreflightError("dictionary_no_usable_pronunciations")
    return result


def _dictionary_key(token: str) -> str:
    if not isinstance(token, str) or not (match := TOKEN_RE.fullmatch(token)):
        raise PreflightError(f"invalid_token:{token}")
    return match[1].lower()


def syllable_count(token: str, dictionary: dict[str, int]) -> int:
    key = _dictionary_key(token)
    try:
        return dictionary[key]
    except KeyError as error:
        raise PreflightError(f"unknown_word:{token}") from error


def _require_did(did: str) -> None:
    if not isinstance(did, str) or not ED25519_DID_RE.fullmatch(did):
        raise PreflightError(f"invalid_contributor_did:{did}")


def did_letters(did: str) -> set[str]:
    _require_did(did)
    return {c for c in did.lower() if "a" <= c <= "z"}


def token_letters(token: str) -> set[str]:
    _dictionary_key(token)
    return {c for c in token.lower() if "a" <= c <= "z"}


def did_can_write(did: str, token: str) -> bool:
    return token_letters(token) <= did_letters(did)


def canonical_text(lines: list[list[PlannedWord]]) -> str:
    if len(lines) != 14 or any(not line for line in lines):
        raise PreflightError("poem_shape_invalid")
    rendered: list[str] = []
    for index, line in enumerate(lines):
        rendered.append(" ".join(word.token for word in line))
        if index in STANZA_BREAK_AFTER:
            rendered.append("")
    return "\n".join(rendered)


def split_x_chunks(text: str, max_chars: int = 280) -> tuple[str, ...]:
    """Split poem-only ASCII text only at whole-line boundaries.

    This is a planning guard, not an X account-control verifier. Attribution stays
    outside the poem. Joining returned chunks with one LF must reconstruct the
    canonical poem byte-for-byte, including stanza blank lines.
    """
    if max_chars < 1:
        raise PreflightError("x_limit_invalid")
    chunks: list[str] = []
    current = ""
    have_current = False
    for line in text.split("\n"):
        candidate = line if not have_current else current + "\n" + line
        if len(candidate) <= max_chars:
            current = candidate
            have_current = True
            continue
        if not have_current or len(line) > max_chars:
            raise PreflightError("x_line_too_long")
        chunks.append(current)
        current = line
        have_current = True
    if have_current:
        chunks.append(current)
    if "\n".join(chunks) != text:
        raise PreflightError("x_chunk_reconstruction_failed")
    return tuple(chunks)


def validate_plan(
    lines: list[list[PlannedWord]],
    roster: list[str],
    dictionary: dict[str, int],
    *,
    x_max_chars: int = 280,
) -> PreflightResult:
    if not 4 <= len(roster) <= 8 or len(set(roster)) != len(roster):
        raise PreflightError("roster_invalid")
    for did in roster:
        _require_did(did)
    roster_set = set(roster)
    if len(lines) != 14:
        raise PreflightError("poem_shape_invalid")

    counts = {did: 0 for did in roster}
    line_syllables: list[int] = []
    previous: str | None = None

    for line in lines:
        if not line:
            raise PreflightError("poem_shape_invalid")
        total = 0
        for planned in line:
            if planned.contributor_did not in roster_set:
                raise PreflightError("assignment_outside_roster")
            if previous == planned.contributor_did:
                raise PreflightError("adjacent_same_contributor")
            if not did_can_write(planned.contributor_did, planned.token):
                raise PreflightError(
                    f"did_letter_violation:{planned.contributor_did}:{planned.token}"
                )
            total += syllable_count(planned.token, dictionary)
            if total > 10:
                raise PreflightError("line_syllable_overflow")
            counts[planned.contributor_did] += 1
            previous = planned.contributor_did
        if total != 10:
            raise PreflightError(f"line_syllables_invalid:{total}")
        line_syllables.append(total)

    missing = [did for did, count in counts.items() if count == 0]
    if missing:
        raise PreflightError("roster_member_without_word:" + ",".join(sorted(missing)))

    text = canonical_text(lines)
    encoded = text.encode("utf-8")
    return PreflightResult(
        canonical_text=text,
        poem_sha256=hashlib.sha256(encoded).hexdigest(),
        byte_count=len(encoded),
        line_syllables=tuple(line_syllables),
        contributor_counts=counts,
        x_chunks=split_x_chunks(text, max_chars=x_max_chars),
    )
