from flop_agent import autopilot

from test_activation_first_contact import cand, setup, write


def test_enabling_first_contact_requires_pause(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path, activation=False)
    try:
        autopilot.set_first_contact_enabled(True)
    except RuntimeError as error:
        assert str(error) == "first-contact enable requires paused autopilot"
    else:
        raise AssertionError("enabling first contact while unpaused must fail closed")


def test_enabling_first_contact_invalidates_resident_revision(monkeypatch, tmp_path):
    rs = setup(monkeypatch, tmp_path, activation=False)
    item = cand(
        "activate",
        category="help_request",
        text="Need test vectors for the DID publish path; happy to help review it.",
    )
    write(rs, item)

    # Establish the no-change fast-path while the cold-contact feature is OFF.
    autopilot.build_outbox()
    before = autopilot.load()
    assert before["resident_revision"] is not None
    assert autopilot.status(before)["queued"] == 0

    autopilot.pause(True)
    result = autopilot.set_first_contact_enabled(True)
    assert result == {"first_contact_enabled": True, "queued": 0}
    assert autopilot.load()["resident_revision"] is None

    autopilot.pause(False)
    assert autopilot.build_outbox()["queued"] == 1
    queued = [
        value
        for value in autopilot.load()["outbox"].values()
        if value.get("status", "queued") == "queued"
    ]
    assert len(queued) == 1
    assert queued[0]["source_candidate_id"] == "activate"
    assert queued[0]["topic"] == "repo_tests_bugs"
