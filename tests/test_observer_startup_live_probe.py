from flop_agent import observer_startup_resilience


def message(seq: int) -> dict:
    return {"seq": seq, "text": "x", "from": "did:key:z6MkAgent"}


def test_unseen_live_contiguity_ignores_old_duplicates_but_rejects_gap():
    assert observer_startup_resilience._unseen_live_is_contiguous([], 50) is True
    assert (
        observer_startup_resilience._unseen_live_is_contiguous(
            [message(49), message(50)], 50
        )
        is True
    )
    assert (
        observer_startup_resilience._unseen_live_is_contiguous(
            [message(49), message(51), message(52)], 50
        )
        is True
    )
    assert (
        observer_startup_resilience._unseen_live_is_contiguous(
            [message(51), message(53)], 50
        )
        is False
    )
    assert (
        observer_startup_resilience._unseen_live_is_contiguous(
            [message(49), message(60)], 50
        )
        is False
    )
