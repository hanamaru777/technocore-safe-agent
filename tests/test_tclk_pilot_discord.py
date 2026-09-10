from flop_agent import discord_tclk_review as review


def test_tclk_stage_and_prepare_commands_stay_authenticated(monkeypatch):
    control = review.Control({"42"}, "99")
    monkeypatch.setattr(review, "_stage_message", lambda offer_id: f"stage:{offer_id}")
    monkeypatch.setattr(review, "_prepare_message", lambda stage_id=None: f"prepare:{stage_id}")

    assert control.command("7", "/tclk-stage offer-1", "99")["error"] == "unauthorized"
    assert control.command("42", "/tclk-stage offer-1", "100")["error"] == "wrong_channel"
    assert control.command("42", "/tclk-stage offer-1", "99")["message"] == "stage:offer-1"
    assert control.command("42", "/tclk-prepare abc", "99")["message"] == "prepare:abc"
    assert control.command("42", "/tclk-prepared", "99")["message"] == "prepare:None"


def test_new_pilot_commands_never_expose_a_write_confirmation_surface():
    control = review.Control({"42"}, "99")
    for command in ("/tclk-stage", "/tclk-prepare", "/tclk-prepared"):
        result = control.command("42", command, "99")
        text = result["message"].lower()
        assert " send" not in text
        assert "confirm" not in text
        assert "approve" not in text


def test_auto_success_notice_explains_stage_without_claiming_accept():
    item = {"id": "0x" + "1" * 64, "job_id": "public-spec-check"}
    verdict = {"seconds_left": 600}
    evidence = {
        "frame_sha256": "a" * 64,
        "full_spec": {"sha256": "b" * 64, "value": "verify public spec document"},
        "material": None,
        "external_url_present": False,
    }
    stage = {"stage_id": "c" * 24}
    text = review._auto_success_notice(item, verdict, evidence, stage, None)
    assert "AUTO-RESOLVE: PASS" in text
    assert "AUTO-STAGE: PASS" in text
    assert stage["stage_id"] in text
    assert "accept・署名・投稿はまだ行いません" in text


def test_prepare_preview_is_public_only():
    preview = {
        "stage_id": "c" * 24,
        "stage_digest": "d" * 64,
        "offer_id": "0x" + "1" * 64,
        "frame_sha256": "a" * 64,
        "full_spec_sha256": "b" * 64,
        "material_sha256": None,
        "accept_line": "tclk1 public-accept-line",
        "accept_sha256": "e" * 64,
        "contract": "0x" + "2" * 64,
        "deal_room": "mb-p-tclk-2222222222222222",
        "expires_ms": review._now_ms() + 600_000,
        "prepared_at": "2026-09-11T00:00:00+00:00",
        "posted": False,
    }
    text = review._preview_message(preview).lower()
    assert "prepare only" in text
    assert "exact accept preview" in text
    assert "preimage" not in text
    assert "private" not in text
