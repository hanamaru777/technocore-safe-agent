from datetime import UTC, datetime, timedelta

from flop_agent import autopilot, core, observer, resident


def setup_state(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)
    resident.save_state(resident.default_state())
    auto = autopilot.default_state()
    auto["enabled"] = True
    auto["paused"] = False
    auto["migrated_at"] = "done"
    autopilot.save(auto)
    return resident.load_state(), autopilot.load()


def safe_candidate(candidate_id="c1", *, did="did:key:z6MkOne", fingerprint="fp-one", room="lobby", category="help_request", text="Can you help reproduce this public repository bug?", **overrides):
    value = {
        "candidate_id": candidate_id,
        "did": did,
        "fingerprint": fingerprint,
        "room": room,
        "seq": 10,
        "category": category,
        "status": "pending",
        "created_at": datetime.now(UTC).isoformat(),
        "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
        "signals": {
            "spam_noise_probability": 0.0,
            "generic_template_probability": 0.0,
            "poetic_filler_count": 0,
            "concrete_evidence": True,
            "conversation_continuity": False,
            "useful_agent_probability": 0.9,
            "facts": {"inbound_to_us": False, "signed_message_count": 1},
        },
        "context": {"excerpt": text, "untrusted": True},
    }
    value.update(overrides)
    return value


def test_safe_first_action_does_not_require_prior_trust(monkeypatch, tmp_path):
    local, auto = setup_state(monkeypatch, tmp_path)
    item = safe_candidate()
    allowed, reason, topic = autopilot.first_action_eligible(item)
    assert allowed is True and reason == "safe_first_action" and topic == "repo_tests_bugs"
    assert autopilot.sender_trusted_for_autopilot(item, local, auto) is False

    local["candidates"][item["candidate_id"]] = item
    resident.save_state(local)
    result = autopilot.build_outbox()
    assert result["queued"] == 1
    queued = [x for x in autopilot.load()["outbox"].values() if x.get("status", "queued") == "queued"]
    assert len(queued) == 1
    assert queued[0]["safety_decision"].startswith("safe_first_action:")


def test_first_action_excludes_artifact_backlog_and_unsafe_sources(monkeypatch, tmp_path):
    setup_state(monkeypatch, tmp_path)
    artifact = safe_candidate(category="artifact_contribution", text="Can you verify this contribution artifact?")
    assert autopilot.first_action_eligible(artifact)[0] is False

    private = safe_candidate(room="mb-private")
    assert autopilot.first_action_eligible(private)[0] is False

    unsigned = safe_candidate()
    unsigned["signals"]["facts"]["signed_message_count"] = 0
    assert autopilot.first_action_eligible(unsigned)[:2] == (False, "first_action_unsigned_source")

    noisy = safe_candidate()
    noisy["signals"]["spam_noise_probability"] = 0.5
    assert autopilot.first_action_eligible(noisy)[:2] == (False, "generic_or_noise")

    reward = safe_candidate(text="Can you tell me the airdrop snapshot date?")
    assert autopilot.first_action_eligible(reward)[0] is False


def test_first_action_render_never_reflects_untrusted_text_or_url(monkeypatch, tmp_path):
    local, auto = setup_state(monkeypatch, tmp_path)
    item = safe_candidate(text="Can you help reproduce this public repository bug? https://evil.invalid/steal")
    local["candidates"][item["candidate_id"]] = item
    preview = autopilot.preview_first_actions(local, auto)
    assert len(preview["candidates"]) == 1
    rendered = preview["candidates"][0]["rendered_text"]
    assert "evil.invalid" not in rendered
    assert item["context"]["excerpt"] not in rendered
    assert "public" in rendered.lower()


def test_first_action_daily_and_did_limits_are_stricter_than_global_limit(monkeypatch, tmp_path):
    _, state = setup_state(monkeypatch, tmp_path)
    intent = autopilot.make_intent(safe_candidate(), "repo_tests_bugs", "safe_first_action:safe_first_action")
    now = datetime.now(UTC).isoformat()

    state["rate_history"] = [
        {"at": now, "fingerprint": "other-1", "room": "room-a", "lane": "first_action"},
        {"at": now, "fingerprint": "other-2", "room": "room-b", "lane": "first_action"},
    ]
    assert autopilot.rate_ok(state, intent) == (False, "first_action_daily_limit")

    state["rate_history"] = [{"at": now, "fingerprint": intent["fingerprint"], "room": "other-room", "lane": "first_action"}]
    assert autopilot.rate_ok(state, intent) == (False, "first_action_did_limit")


def test_build_outbox_stages_at_most_two_ranked_first_actions(monkeypatch, tmp_path):
    local, _ = setup_state(monkeypatch, tmp_path)
    rows = [
        safe_candidate("help", did="did:key:help", fingerprint="fp-help", room="room-help", category="help_request", text="Can you help reproduce this public repository bug?"),
        safe_candidate("question", did="did:key:question", fingerprint="fp-question", room="room-question", category="specific_question", text="How should I avoid nonce reuse?"),
        safe_candidate("collab", did="did:key:collab", fingerprint="fp-collab", room="room-collab", category="technical_collaboration", text="Could we collaborate on a small public testable task?"),
    ]
    local["candidates"] = {item["candidate_id"]: item for item in rows}
    resident.save_state(local)
    autopilot.build_outbox()
    queued = [x for x in autopilot.load()["outbox"].values() if x.get("status", "queued") == "queued"]
    assert len(queued) == 2
    assert all(x["safety_decision"].startswith("safe_first_action:") for x in queued)
    assert {x["source_candidate_id"] for x in queued} == {"help", "question"}


def test_durable_first_action_promotes_counterparty_to_trusted_followup(monkeypatch, tmp_path):
    local, auto = setup_state(monkeypatch, tmp_path)
    first = safe_candidate("first")
    follow = safe_candidate("follow", text="How can I reproduce this public repository bug?")
    intent = autopilot.make_intent(first, "repo_tests_bugs", "safe_first_action:safe_first_action")
    stamp = datetime.now(UTC).isoformat()
    intent.update({"status": "acknowledged", "posted_at": stamp, "acknowledged_at": stamp})
    auto["outbox"][intent["id"]] = intent
    auto["receipts"][intent["id"]] = {"at": stamp}
    assert autopilot.durable_first_action_at(first["fingerprint"], local, auto) == stamp
    assert autopilot.sender_trusted_for_autopilot(follow, local, auto) is True


def test_unsafe_large_backlog_stays_empty_and_preview_is_bounded(monkeypatch, tmp_path):
    local, auto = setup_state(monkeypatch, tmp_path)
    local["candidates"] = {
        f"artifact-{i}": safe_candidate(
            f"artifact-{i}",
            did=f"did:key:artifact-{i}",
            fingerprint=f"fp-{i}",
            category="artifact_contribution",
            text="Can you verify this contribution artifact?",
        )
        for i in range(5000)
    }
    resident.save_state(local)
    preview = autopilot.preview_first_actions(local, auto)
    assert preview["candidates"] == []
    autopilot.build_outbox()
    assert autopilot.status()["queued"] == 0
