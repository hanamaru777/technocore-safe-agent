import pytest

from flop_agent import sonnet_planner as planner


_PAYLOAD = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstu"
BROAD = [
    "did:key:z6Mk" + _PAYLOAD,
    "did:key:z6Mk" + _PAYLOAD[:-1] + "v",
    "did:key:z6Mk" + _PAYLOAD[:-1] + "w",
    "did:key:z6Mk" + _PAYLOAD[:-1] + "x",
]
LIMITED = "did:key:z6Mk" + "A" * 44


def _lines(token="golden"):
    return [[token] * 5 for _ in range(14)]


def _dictionary():
    return {
        "golden": 2,
        "river": 2,
        "quiet": 2,
        "a": 1,
    }


def test_assignment_is_feasible_deterministic_balanced_and_uses_every_member():
    lines = _lines()
    result = planner.assign_words(lines, BROAD)
    flat = [planned for line in result.lines for planned in line]

    assert len(flat) == 70
    assert all(a.contributor_did != b.contributor_did for a, b in zip(flat, flat[1:]))
    assert set(result.contributor_counts) == set(BROAD)
    assert all(count > 0 for count in result.contributor_counts.values())
    assert result.balance_spread <= 1
    assert planner.assign_words(lines, BROAD) == result


def test_solve_and_validate_delegates_exact_ten_mechanics_to_preflight():
    assignment, mechanical = planner.solve_and_validate(_lines(), BROAD, _dictionary())
    assert assignment.balance_spread <= 1
    assert mechanical.line_syllables == (10,) * 14
    assert mechanical.contributor_counts == assignment.contributor_counts


def test_no_eligible_contributor_returns_exact_blocking_token_and_missing_letters():
    roster = [
        LIMITED,
        "did:key:z6Mk" + "B" * 44,
        "did:key:z6Mk" + "C" * 44,
        "did:key:z6Mk" + "D" * 44,
    ]
    lines = _lines("river")
    with pytest.raises(planner.PlanningError, match="token_has_no_eligible_contributor") as caught:
        planner.assign_words(lines, roster)

    first = caught.value.blocking[0]
    assert first.flat_index == 0
    assert first.line_index == 0
    assert first.word_index == 0
    assert first.token == "river"
    assert all(value for value in first.missing_letters_by_did.values())
    assert "r" in first.missing_letters_by_did[LIMITED]


def test_roster_member_with_zero_possible_words_fails_before_assignment():
    roster = [LIMITED, BROAD[1], BROAD[2], BROAD[3]]
    with pytest.raises(planner.PlanningError, match="roster_member_unassignable"):
        planner.assign_words(_lines("river"), roster)


def test_global_adjacency_unsatisfiable_fails_closed():
    one = "did:key:z6Mk" + "RIVER" * 8 + "RIVE"
    others = [
        "did:key:z6Mk" + "A" * 44,
        "did:key:z6Mk" + "B" * 44,
        "did:key:z6Mk" + "C" * 44,
    ]
    roster = [one, *others]
    assert len(one.removeprefix("did:key:z6Mk")) == 44
    with pytest.raises(planner.PlanningError):
        planner.assign_words(_lines("river"), roster)


def test_literary_readiness_is_explicitly_manual_and_checks_seven_families():
    lines = _lines()
    pending = planner.literary_readiness(lines)
    assert pending.rhyme_review == "REVIEW_REQUIRED"
    assert pending.meter_review == "REVIEW_REQUIRED"

    families = [
        "oon", "old", "oon", "old",
        "air", "ight", "air", "ight",
        "ee", "ame", "ee", "ame",
        "end", "end",
    ]
    reviewed = planner.literary_readiness(
        lines,
        rhyme_families=families,
        meter_ok=[True] * 14,
    )
    assert reviewed.rhyme_review == "PASS"
    assert reviewed.meter_review == "PASS"
    assert reviewed.issues == ()

    bad = list(families)
    bad[2] = "wrong"
    failed = planner.literary_readiness(
        lines,
        rhyme_families=bad,
        meter_ok=[True] * 14,
    )
    assert failed.rhyme_review == "FAIL"


def test_publication_readiness_never_claims_live_x_or_referee_checks_without_evidence():
    _, mechanical = planner.solve_and_validate(_lines(), BROAD, _dictionary())
    readiness = planner.publication_readiness(mechanical)
    assert readiness.canonical_text == mechanical.canonical_text
    assert len(readiness.unresolved) == 4

    verified = planner.publication_readiness(
        mechanical,
        final_contributor_is_last_accepted_writer=True,
        registered_x_account_control_verified=True,
        published_exact_canonical_poem_verified=True,
        referee_submission_receipt_verified=True,
    )
    assert verified.unresolved == ()
