"""Planning-only roster assignment and literary/submission readiness helpers.

No function in this module signs, posts, requests a room, consents to a roster,
or writes to X.  It builds on :mod:`sonnet_preflight` and exists only to finish
as much deterministic planning as possible before the first accepted word.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from . import sonnet_preflight as preflight

EXPECTED_RHYME_SCHEME = tuple("ABABCDCDEFEFGG")


class PlanningError(ValueError):
    def __init__(self, message: str, *, blocking: tuple["BlockingToken", ...] = ()):
        super().__init__(message)
        self.blocking = blocking


@dataclass(frozen=True)
class BlockingToken:
    flat_index: int
    line_index: int
    word_index: int
    token: str
    missing_letters_by_did: dict[str, str]


@dataclass(frozen=True)
class AssignmentResult:
    lines: tuple[tuple[preflight.PlannedWord, ...], ...]
    contributor_counts: dict[str, int]
    balance_spread: int


@dataclass(frozen=True)
class LiteraryReadiness:
    expected_scheme: tuple[str, ...]
    end_tokens: tuple[str, ...]
    rhyme_review: str
    meter_review: str
    issues: tuple[str, ...]


@dataclass(frozen=True)
class PublicationReadiness:
    canonical_text: str
    poem_sha256: str
    byte_count: int
    x_chunks: tuple[str, ...]
    checks: tuple[str, ...]
    unresolved: tuple[str, ...]


def _validate_roster(roster: list[str]) -> None:
    if not 4 <= len(roster) <= 8 or len(set(roster)) != len(roster):
        raise PlanningError("roster_invalid")
    for did in roster:
        try:
            preflight.did_letters(did)
        except preflight.PreflightError as error:
            raise PlanningError(str(error)) from error


def _flatten(lines: list[list[str]]) -> tuple[list[str], list[tuple[int, int]]]:
    if len(lines) != 14 or any(not line for line in lines):
        raise PlanningError("poem_shape_invalid")
    tokens: list[str] = []
    positions: list[tuple[int, int]] = []
    for line_index, line in enumerate(lines):
        for word_index, token in enumerate(line):
            try:
                preflight.token_letters(token)
            except preflight.PreflightError as error:
                raise PlanningError(str(error)) from error
            tokens.append(token)
            positions.append((line_index, word_index))
    return tokens, positions


def eligible_contributors(token: str, roster: list[str]) -> tuple[str, ...]:
    _validate_roster(roster)
    return tuple(did for did in roster if preflight.did_can_write(did, token))


def _blocking_tokens(
    tokens: list[str],
    positions: list[tuple[int, int]],
    roster: list[str],
) -> tuple[BlockingToken, ...]:
    blocked: list[BlockingToken] = []
    for flat_index, token in enumerate(tokens):
        required = preflight.token_letters(token)
        if any(required <= preflight.did_letters(did) for did in roster):
            continue
        line_index, word_index = positions[flat_index]
        missing = {
            did: "".join(sorted(required - preflight.did_letters(did)))
            for did in roster
        }
        blocked.append(
            BlockingToken(
                flat_index=flat_index,
                line_index=line_index,
                word_index=word_index,
                token=token,
                missing_letters_by_did=missing,
            )
        )
    return tuple(blocked)


def assign_words(lines: list[list[str]], roster: list[str]) -> AssignmentResult:
    """Assign every planned token to a roster DID deterministically.

    Exact feasibility is checked with a suffix DP over ``(position, previous DID,
    used roster mask)``.  Among feasible next contributors, the least-used DID is
    chosen first, which gives a deterministic balance preference without ever
    sacrificing feasibility.
    """
    _validate_roster(roster)
    tokens, positions = _flatten(lines)
    blocked = _blocking_tokens(tokens, positions, roster)
    if blocked:
        raise PlanningError("token_has_no_eligible_contributor", blocking=blocked)

    eligibility: list[tuple[int, ...]] = []
    member_positions = [0] * len(roster)
    for token in tokens:
        allowed = tuple(
            index
            for index, did in enumerate(roster)
            if preflight.did_can_write(did, token)
        )
        eligibility.append(allowed)
        for index in allowed:
            member_positions[index] += 1

    unavailable = [roster[i] for i, count in enumerate(member_positions) if count == 0]
    if unavailable:
        raise PlanningError("roster_member_unassignable:" + ",".join(unavailable))

    full_mask = (1 << len(roster)) - 1

    @lru_cache(maxsize=None)
    def feasible(position: int, previous: int, used_mask: int) -> bool:
        if position == len(tokens):
            return used_mask == full_mask
        for contributor in eligibility[position]:
            if contributor == previous:
                continue
            if feasible(
                position + 1,
                contributor,
                used_mask | (1 << contributor),
            ):
                return True
        return False

    if not feasible(0, -1, 0):
        raise PlanningError("assignment_unsatisfiable")

    counts = [0] * len(roster)
    chosen: list[int] = []
    used_mask = 0
    previous = -1

    for position in range(len(tokens)):
        candidates = sorted(
            (index for index in eligibility[position] if index != previous),
            key=lambda index: (counts[index], index),
        )
        selected = None
        for contributor in candidates:
            next_mask = used_mask | (1 << contributor)
            if feasible(position + 1, contributor, next_mask):
                selected = contributor
                break
        if selected is None:  # defensive: exact suffix feasibility said one exists
            raise PlanningError("assignment_solver_internal_error")
        chosen.append(selected)
        counts[selected] += 1
        used_mask |= 1 << selected
        previous = selected

    planned_lines: list[tuple[preflight.PlannedWord, ...]] = []
    cursor = 0
    for source_line in lines:
        planned_line: list[preflight.PlannedWord] = []
        for token in source_line:
            contributor = chosen[cursor]
            planned_line.append(preflight.PlannedWord(token, roster[contributor]))
            cursor += 1
        planned_lines.append(tuple(planned_line))

    count_map = {did: counts[index] for index, did in enumerate(roster)}
    return AssignmentResult(
        lines=tuple(planned_lines),
        contributor_counts=count_map,
        balance_spread=max(counts) - min(counts),
    )


def solve_and_validate(
    lines: list[list[str]],
    roster: list[str],
    dictionary: dict[str, int],
    *,
    x_max_chars: int = 280,
) -> tuple[AssignmentResult, preflight.PreflightResult]:
    assignment = assign_words(lines, roster)
    mutable_lines = [list(line) for line in assignment.lines]
    result = preflight.validate_plan(
        mutable_lines,
        roster,
        dictionary,
        x_max_chars=x_max_chars,
    )
    return assignment, result


def _end_token(line: list[str]) -> str:
    if not line:
        raise PlanningError("poem_shape_invalid")
    token = line[-1]
    match = preflight.TOKEN_RE.fullmatch(token)
    if not match:
        raise PlanningError(f"invalid_token:{token}")
    return match[1].lower()


def literary_readiness(
    lines: list[list[str]],
    *,
    rhyme_families: list[str] | None = None,
    meter_ok: list[bool] | None = None,
) -> LiteraryReadiness:
    """Record literary review without pretending it is an official validator.

    ``rhyme_families`` and ``meter_ok`` are reviewer inputs.  This function only
    checks that the supplied judgments are internally consistent with the target
    scheme.  It never claims to replace FLOP's human literary judgment.
    """
    if len(lines) != 14 or any(not line for line in lines):
        raise PlanningError("poem_shape_invalid")
    end_tokens = tuple(_end_token(line) for line in lines)
    issues: list[str] = []

    if rhyme_families is None:
        rhyme_review = "REVIEW_REQUIRED"
        issues.append("rhyme_manual_review_required")
    else:
        if len(rhyme_families) != 14 or any(not value for value in rhyme_families):
            raise PlanningError("rhyme_family_review_invalid")
        mapping: dict[str, str] = {}
        reverse: dict[str, str] = {}
        rhyme_ok = True
        for expected, actual in zip(EXPECTED_RHYME_SCHEME, rhyme_families):
            prior = mapping.setdefault(expected, actual)
            if prior != actual:
                rhyme_ok = False
            other = reverse.setdefault(actual, expected)
            if other != expected:
                rhyme_ok = False
        if len(mapping) != 7 or len(set(mapping.values())) != 7:
            rhyme_ok = False
        rhyme_review = "PASS" if rhyme_ok else "FAIL"
        if not rhyme_ok:
            issues.append("rhyme_scheme_or_distinct_family_review_failed")

    if meter_ok is None:
        meter_review = "REVIEW_REQUIRED"
        issues.append("iambic_meter_manual_review_required")
    else:
        if len(meter_ok) != 14:
            raise PlanningError("meter_review_invalid")
        meter_review = "PASS" if all(meter_ok) else "FAIL"
        if meter_review == "FAIL":
            issues.append("iambic_meter_review_failed")

    return LiteraryReadiness(
        expected_scheme=EXPECTED_RHYME_SCHEME,
        end_tokens=end_tokens,
        rhyme_review=rhyme_review,
        meter_review=meter_review,
        issues=tuple(issues),
    )


def publication_readiness(
    mechanical: preflight.PreflightResult,
    *,
    final_contributor_is_last_accepted_writer: bool | None = None,
    registered_x_account_control_verified: bool | None = None,
    published_exact_canonical_poem_verified: bool | None = None,
    referee_submission_receipt_verified: bool | None = None,
) -> PublicationReadiness:
    """Build a fail-visible publication checklist from official protocol gates."""
    checks = (
        "final contributor must be the last accepted word contributor",
        "publication must use that contributor's registered public X account",
        "published poem must equal the exact frozen canonical poem",
        "attribution belongs outside the poem",
        "signed submission packet must receive a referee receipt before closing",
    )
    status = {
        "final_contributor_last_writer": final_contributor_is_last_accepted_writer,
        "registered_x_account_control": registered_x_account_control_verified,
        "exact_canonical_x_publication": published_exact_canonical_poem_verified,
        "referee_submission_receipt": referee_submission_receipt_verified,
    }
    unresolved = tuple(
        key if value is None else key + "=FAIL"
        for key, value in status.items()
        if value is not True
    )
    return PublicationReadiness(
        canonical_text=mechanical.canonical_text,
        poem_sha256=mechanical.poem_sha256,
        byte_count=mechanical.byte_count,
        x_chunks=mechanical.x_chunks,
        checks=checks,
        unresolved=unresolved,
    )
