from flop_agent import discord_tclk_review as review


def test_tclk_resolve_command_requires_allowed_user_and_channel(monkeypatch):
    control = review.Control({"42"}, "99")
    monkeypatch.setattr(review, "_resolved_note_message", lambda offer_id: f"resolved:{offer_id}")

    wrong_user = control.command("7", "/tclk-resolve offer-1", "99")
    assert wrong_user["ok"] is False
    assert wrong_user["error"] == "unauthorized"

    wrong_channel = control.command("42", "/tclk-resolve offer-1", "100")
    assert wrong_channel["ok"] is False
    assert wrong_channel["error"] == "wrong_channel"

    accepted_review = control.command("42", "/tclk-resolve offer-1", "99")
    assert accepted_review == {"ok": True, "data": {}, "message": "resolved:offer-1"}


def test_tclk_resolve_usage_is_fixed_shape():
    control = review.Control({"42"}, "99")
    result = control.command("42", "/tclk-resolve", "99")
    assert result["ok"] is False
    assert result["error"] == "invalid_args"
    assert result["message"] == "Usage: /tclk-resolve <offer-id>"


def test_install_binds_only_review_control_not_signer_or_protocol_writer(monkeypatch):
    monkeypatch.setattr(review.app, "Control", review._BaseControl)
    review.install()
    assert review.app.Control is review.Control
    assert not hasattr(review.Control, "sign")
    assert not hasattr(review.Control, "accept")
    assert not hasattr(review.Control, "lock")
    assert not hasattr(review.Control, "reveal")
