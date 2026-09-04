from flop_agent import autopilot

from test_activation_first_contact import cand, setup


def test_did_publish_test_vector_help_uses_existing_repo_template(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    item = cand(
        "quality",
        category="help_request",
        text=(
            "solid work. onboarding's the lever that moves everything else. "
            "need a second pair of eyes on the flow, test vectors for the DID publish path, "
            "or just someone to run through it fresh? happy to help wherever the friction is."
        ),
    )
    allowed, reason, topic = autopilot.first_contact_eligible(item)
    assert (allowed, reason, topic) == (
        True,
        "concrete_public_technical_request",
        "repo_tests_bugs",
    )
    rendered = autopilot.render(autopilot.make_intent(item, topic, reason))
    assert "public repository" in rendered
    assert "independently verifiable public evidence" in rendered
    assert item["context"]["excerpt"] not in rendered
