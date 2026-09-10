from flop_agent import observer_tclk_parser_guard as guard, tclk_watch


def _reset(monkeypatch):
    monkeypatch.setattr(guard, "_NEXT_PARSE_AT", 0.0)
    monkeypatch.setattr(guard, "_INSTALLED", False)


def test_guard_admits_at_most_one_candidate_per_interval(monkeypatch):
    _reset(monkeypatch)
    calls = []
    now = {"value": 100.0}

    monkeypatch.setattr(guard.time, "monotonic", lambda: now["value"])
    monkeypatch.setattr(
        guard,
        "_BASE_OFFICIAL_OFFER",
        lambda text: calls.append(text) or {"frame": text},
    )

    first = guard.bounded_official_offer("tclk1 first")
    second = guard.bounded_official_offer("tclk1 second")

    assert first == {"frame": "tclk1 first"}
    assert second is None
    assert calls == ["tclk1 first"]

    now["value"] += guard.MIN_PARSE_INTERVAL_SECONDS - 0.01
    assert guard.bounded_official_offer("tclk1 third") is None
    assert calls == ["tclk1 first"]

    now["value"] += 0.01
    fourth = guard.bounded_official_offer("tclk1 fourth")
    assert fourth == {"frame": "tclk1 fourth"}
    assert calls == ["tclk1 first", "tclk1 fourth"]


def test_guard_does_not_spend_slot_on_non_candidate(monkeypatch):
    _reset(monkeypatch)
    calls = []
    now = {"value": 200.0}

    monkeypatch.setattr(guard.time, "monotonic", lambda: now["value"])
    monkeypatch.setattr(
        guard,
        "_BASE_OFFICIAL_OFFER",
        lambda text: calls.append(text) or None,
    )

    assert guard.bounded_official_offer("ordinary text") is None
    assert guard._NEXT_PARSE_AT == 0.0

    assert guard.bounded_official_offer("tclk1 candidate") is None
    assert guard._NEXT_PARSE_AT == 200.0 + guard.MIN_PARSE_INTERVAL_SECONDS
    assert calls == ["ordinary text", "tclk1 candidate"]


def test_install_patches_only_tclk_parser_admission(monkeypatch):
    _reset(monkeypatch)
    original = tclk_watch.official_offer
    monkeypatch.setattr(tclk_watch, "official_offer", original)

    guard.install()
    assert tclk_watch.official_offer is guard.bounded_official_offer

    guard.install()
    assert tclk_watch.official_offer is guard.bounded_official_offer
