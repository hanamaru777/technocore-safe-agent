import hashlib

import pytest

from flop_agent import sonnet_preflight as s


DIDS = [
    "did:key:abcdefghijklmnopqrstuvwxyz",
    "did:key:bcdefghijklmnopqrstuvwxyza",
    "did:key:cdefghijklmnopqrstuvwxyzab",
    "did:key:defghijklmnopqrstuvwxyzabc",
]


def _dictionary():
    return {
        "a": 1,
        "bright": 1,
        "calm": 1,
        "day": 1,
        "golden": 2,
        "river": 2,
        "quiet": 2,
    }


def _plan():
    # 5 x two-syllable words per line = exactly ten syllables.
    words = ["golden", "river", "quiet", "golden", "river"]
    lines = []
    flat_index = 0
    for _ in range(14):
        line = []
        for token in words:
            line.append(s.PlannedWord(token, DIDS[flat_index % len(DIDS)]))
            flat_index += 1
        lines.append(line)
    return lines


def test_parse_cmudict_uses_largest_pronunciation_count():
    raw = (
        b"WORD W ER1 D\n"
        b"WORD(1) W ER1 D AH0\n"
        b"QUIET K W AY1 AH0 T\n"
    )
    parsed = s.parse_cmudict(raw)
    assert parsed["word"] == 2
    assert parsed["quiet"] == 2


def test_verify_cmudict_rejects_wrong_hash(tmp_path):
    path = tmp_path / "cmudict.dict"
    path.write_bytes(b"not the frozen dictionary")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(s.PreflightError, match=f"cmudict_sha256_mismatch:{digest}"):
        s.verify_cmudict(path)


def test_validate_plan_produces_exact_shape_hash_and_balanced_presence():
    result = s.validate_plan(_plan(), DIDS, _dictionary())
    assert result.line_syllables == (10,) * 14
    assert set(result.contributor_counts) == set(DIDS)
    assert all(count > 0 for count in result.contributor_counts.values())
    assert result.byte_count == len(result.canonical_text.encode("utf-8"))
    assert result.poem_sha256 == hashlib.sha256(
        result.canonical_text.encode("utf-8")
    ).hexdigest()
    assert result.canonical_text.count("\n\n") == 3
    assert not result.canonical_text.endswith("\n")
    assert all(len(chunk) <= 280 for chunk in result.x_chunks)


def test_unknown_word_fails_closed():
    lines = _plan()
    lines[0][0] = s.PlannedWord("mystery", DIDS[0])
    with pytest.raises(s.PreflightError, match="unknown_word:mystery"):
        s.validate_plan(lines, DIDS, _dictionary())


def test_did_letter_violation_fails_closed():
    roster = [
        "did:key:abcde",
        DIDS[1],
        DIDS[2],
        DIDS[3],
    ]
    lines = _plan()
    lines[0][0] = s.PlannedWord("river", roster[0])
    for line in lines:
        for i, planned in enumerate(line):
            if planned.contributor_did == DIDS[0]:
                line[i] = s.PlannedWord(planned.token, roster[0])
    with pytest.raises(s.PreflightError, match="did_letter_violation"):
        s.validate_plan(lines, roster, _dictionary())


def test_adjacent_same_contributor_fails_closed():
    lines = _plan()
    lines[0][1] = s.PlannedWord(lines[0][1].token, lines[0][0].contributor_did)
    with pytest.raises(s.PreflightError, match="adjacent_same_contributor"):
        s.validate_plan(lines, DIDS, _dictionary())


def test_member_without_word_fails_closed():
    lines = _plan()
    absent = DIDS[3]
    replacements = [DIDS[0], DIDS[1], DIDS[2]]
    cursor = 0
    previous = None
    for line in lines:
        for i, planned in enumerate(line):
            if planned.contributor_did == absent:
                while replacements[cursor % 3] == previous:
                    cursor += 1
                line[i] = s.PlannedWord(planned.token, replacements[cursor % 3])
                cursor += 1
            previous = line[i].contributor_did
    with pytest.raises(s.PreflightError, match="roster_member_without_word"):
        s.validate_plan(lines, DIDS, _dictionary())


def test_line_overflow_and_underflow_fail_closed():
    overflow = _plan()
    overflow[0].append(s.PlannedWord("a", DIDS[2]))
    with pytest.raises(s.PreflightError, match="line_syllable_overflow"):
        s.validate_plan(overflow, DIDS, _dictionary())

    underflow = _plan()
    underflow[0].pop()
    with pytest.raises(s.PreflightError, match="line_syllables_invalid:8"):
        s.validate_plan(underflow, DIDS, _dictionary())


def test_x_chunking_never_splits_inside_a_line():
    text = "12345\n67890\nabcde"
    assert s.split_x_chunks(text, max_chars=11) == ("12345\n67890", "abcde")
    with pytest.raises(s.PreflightError, match="x_line_too_long"):
        s.split_x_chunks("123456", max_chars=5)
