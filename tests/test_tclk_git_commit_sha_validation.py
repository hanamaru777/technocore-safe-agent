import hashlib

import pytest

from flop_agent import tclk_pilot_accept as accept
from flop_agent import tclk_pilot_reveal_publish as reveal


GIT_SHA = "a" * 40
DID = "did:key:z6Mk" + "1" * 44
SIG = "A" * 86
OFFER_ID = "0x" + "2" * 64
CONTRACT_ID = "0x" + "3" * 64
ACCEPT_LINE = 'tclk1 {"type":"accept"}'
ACCEPT_SHA = hashlib.sha256(ACCEPT_LINE.encode()).hexdigest()


def accept_state(git_sha=GIT_SHA):
    return {
        "schema_version": 1,
        "state": "prepared",
        "stage_id": "4" * 32,
        "approval_digest": "5" * 64,
        "offer_id": OFFER_ID,
        "accept_line": ACCEPT_LINE,
        "accept_sha256": ACCEPT_SHA,
        "contract_id": CONTRACT_ID,
        "deal_room": "mb-p-tclk-" + "6" * 16,
        "did": DID,
        "nonce": "123",
        "sig": SIG,
        "prepared_at": "2033-05-18T03:33:20+00:00",
        "attempted_at": None,
        "posted_at": None,
        "seq": None,
        "ts": None,
        "last_error": None,
        "git_commit_sha": git_sha,
        "executed_at": "2033-05-18T03:33:20+00:00",
    }


def reveal_state(git_sha=GIT_SHA):
    return {
        "schema_version": 1,
        "state": "prepared",
        "stage_id": "4" * 32,
        "approval_digest": "5" * 64,
        "offer_id": OFFER_ID,
        "contract_id": CONTRACT_ID,
        "deal_room": "mb-p-tclk-" + "6" * 16,
        "did": DID,
        "reveal_sha256": "7" * 64,
        "nonce": "123",
        "sig": SIG,
        "prepared_at": "2033-05-18T03:33:20+00:00",
        "reveal_attempted_at": None,
        "reveal_posted_at": None,
        "reveal_seq": None,
        "reveal_ts": None,
        "claim_attempted_at": None,
        "claimed_at": None,
        "locked_note_sha256": None,
        "claimed_note_sha256": None,
        "last_error": None,
        "git_commit_sha": git_sha,
        "executed_at": "2033-05-18T03:33:20+00:00",
    }


def test_accept_state_accepts_real_shaped_git_sha_and_rejects_wrong_lengths():
    assert accept._validate_state(accept_state())["git_commit_sha"] == GIT_SHA
    for bad in ("a" * 39, "a" * 41, "a" * 64):
        with pytest.raises(accept.AcceptError, match="accept_state_invalid"):
            accept._validate_state(accept_state(bad))


def test_reveal_state_accepts_real_shaped_git_sha_and_rejects_wrong_lengths():
    assert reveal._validate_state(reveal_state())["git_commit_sha"] == GIT_SHA
    for bad in ("a" * 39, "a" * 41, "a" * 64):
        with pytest.raises(reveal.RevealPublishError, match="reveal_publish_state_invalid"):
            reveal._validate_state(reveal_state(bad))
