from flop_agent import discord_knowledge


def _offer() -> dict:
    full = (
        "review public task "
        + ("x" * 2300)
        + " https://evil.invalid/path @everyone FULL-TERMS-TAIL"
    )
    return {
        "id": "offer-1",
        "counterpart_fingerprint": "abcdef1234567890",
        "frame_type": "offer",
        "job_proto": "a2a",
        "job_id": "public-review",
        "amount": "200",
        "asset": "FLOP",
        "rail": "paper",
        "expires_ms": 4102444800000,
        "terms": full[:280],
        "terms_full": full,
        "frame_sha256": "a" * 64,
        "read_only": True,
        "accepted": False,
    }


def _setup(monkeypatch, offer: dict) -> None:
    monkeypatch.setattr(discord_knowledge.tclk_watch, "runtime_status", lambda: {"ready": True, "reason": None})
    monkeypatch.setattr(discord_knowledge.observer, "load_state", lambda: {})
    monkeypatch.setattr(discord_knowledge.tclk_watch, "offer", lambda _state, _offer_id: offer)
    monkeypatch.setattr(discord_knowledge.tclk_watch, "opportunities", lambda _state: [offer])


def test_tclk_detail_shows_complete_sanitized_locally_retained_terms(monkeypatch):
    offer = _offer()
    _setup(monkeypatch, offer)
    control = discord_knowledge.Control({"42"}, "99")

    result = control.command("42", "/tclk offer-1", "99")

    assert result["ok"] is True
    message = result["message"]
    assert "FULL-TERMS-TAIL" in message
    assert "https://evil.invalid" not in message
    assert "[URL省略]" in message
    assert "@everyone" not in message
    assert "[mention省略]" in message
    assert "stored full terms" in message
    assert "frame sha256: " + ("a" * 64) in message
    assert "did not accept, sign, post, lock, reveal, or pay" in message

    chunks = discord_knowledge.base.base.discord_message_chunks(message)
    assert len(chunks) > 1
    assert all(len(chunk) <= 2000 for chunk in chunks)


def test_tclk_opportunities_list_stays_concise(monkeypatch):
    offer = _offer()
    _setup(monkeypatch, offer)
    control = discord_knowledge.Control({"42"}, "99")

    result = control.command("42", "/tclk-opportunities", "99")

    assert result["ok"] is True
    assert "FULL-TERMS-TAIL" not in result["message"]
    assert "terms (untrusted):" in result["message"]
    assert len(result["message"]) < 2000


def test_tclk_detail_keeps_control_access_boundary(monkeypatch):
    offer = _offer()
    _setup(monkeypatch, offer)
    control = discord_knowledge.Control({"42"}, "99")

    unauthorized = control.command("7", "/tclk offer-1", "99")
    wrong_channel = control.command("42", "/tclk offer-1", "100")

    assert unauthorized["ok"] is False
    assert unauthorized["error"] == "unauthorized"
    assert wrong_channel["ok"] is False
    assert wrong_channel["error"] == "wrong_channel"
