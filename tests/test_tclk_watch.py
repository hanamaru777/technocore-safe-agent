import json
import secrets
import subprocess
from datetime import UTC, datetime

from flop_agent import core, discord_control, observer, tclk_watch


def setup(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    observer.atomic_json_write(observer.config_path(), observer.DEFAULT_CONFIG)


def signed_offer(**changes):
    """Create fixture frames using the pinned official tclk package, never a local encoder."""
    source = """
import { makeOffer, encodeFrame } from '@flop-labs/tclk';
let input = ''; for await (const chunk of process.stdin) input += chunk;
const change = JSON.parse(input || '{}');
const now = Date.now();
const base = {from: change.from || 'did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB', role: 'payer', amount: '1', asset: 'PAPER', lock: 'hash', rails: ['paper'], claimByMs: now + 60000, refundAfterMs: now + 120000, expiresMs: now + 180000, job: {proto: 'test-job', id: 'job-1', context: 'artifact terms'}, nonce: 'abcdef12'};
console.log(encodeFrame(makeOffer({...base, ...change, job: {...base.job, ...(change.job || {})}})));
"""
    result = subprocess.run(["node", "--input-type=module", "--eval", source], input=json.dumps(changes), text=True, capture_output=True, check=True)
    return result.stdout.strip()


def signed_offer_message(monkeypatch, *, seq=1, frame_from=None, **changes):
    """Use a fresh dummy seed and the preserved official signer for transport proof."""
    seed = secrets.token_hex(32)
    monkeypatch.setenv("SIGN_SEED", seed)
    transport_from = core.current_did()
    frame = signed_offer(**{"from": frame_from or transport_from, **changes})
    monkeypatch.setenv("SIGN_SEED", seed)
    signed_from, signature = core.invoke_signer("say", tclk_watch.OFFER_ROOM, str(seq), frame)
    assert signed_from == transport_from
    return {"seq": seq, "from": transport_from, "nonce": str(seq), "sig": signature, "text": frame, "ts": datetime.now(UTC).isoformat()}


def test_valid_signed_paper_offer_is_read_only_opportunity(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    state = observer.default_state()
    observer.process_message(state, observer.DEFAULT_CONFIG, tclk_watch.OFFER_ROOM, signed_offer_message(monkeypatch), None, None)
    rows = tclk_watch.opportunities(state)
    assert len(rows) == 1
    item = rows[0]
    assert item["frame_type"] == "offer" and item["rail"] == "paper"
    assert item["read_only"] is True and item["accepted"] is False
    assert not any(key in item for key in ("seed", "payment_key", "signature"))
    assert not state["agents"] and [event["kind"] for event in state["opportunities"]] == ["tclk_offer"]


def test_tclk_protocol_frame_never_enters_generic_lane(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    state = observer.default_state()
    record = signed_offer_message(monkeypatch, job={"context": "help? collaboration contribution"})
    observer.process_message(state, observer.DEFAULT_CONFIG, tclk_watch.OFFER_ROOM, record, None, None)
    assert len(tclk_watch.opportunities(state)) == 1
    assert not state["agents"]
    assert state["metrics"]["questions_detected"] == state["metrics"]["help_candidates"] == state["metrics"]["collab_candidates"] == state["metrics"]["contribution_candidates"] == 0


def test_unsigned_malformed_mismatched_replay_and_unsupported_frames_fail_closed(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    state = observer.default_state()
    valid = signed_offer_message(monkeypatch)
    unsigned = {key: value for key, value in valid.items() if key != "sig"}
    mismatch = signed_offer_message(monkeypatch, seq=2, frame_from=valid["from"])
    malformed = {**valid, "seq": 3, "text": "tclk1 {broken"}
    unsupported = signed_offer_message(monkeypatch, seq=4, rails=["x402"])
    observer.process_message(state, observer.DEFAULT_CONFIG, tclk_watch.OFFER_ROOM, unsigned, None, None)
    observer.process_message(state, observer.DEFAULT_CONFIG, tclk_watch.OFFER_ROOM, mismatch, None, None)
    observer.process_message(state, observer.DEFAULT_CONFIG, tclk_watch.OFFER_ROOM, malformed, None, None)
    observer.process_message(state, observer.DEFAULT_CONFIG, tclk_watch.OFFER_ROOM, unsupported, None, None)
    observer.process_message(state, observer.DEFAULT_CONFIG, "lobby", valid, None, None)
    assert tclk_watch.opportunities(state) == []
    observer.process_message(state, observer.DEFAULT_CONFIG, tclk_watch.OFFER_ROOM, valid, None, None)
    observer.process_message(state, observer.DEFAULT_CONFIG, tclk_watch.OFFER_ROOM, valid, None, None)
    assert len(tclk_watch.opportunities(state)) == 1


def test_discord_tclk_views_sanitize_and_never_write_state(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    state = observer.default_state()
    record = signed_offer_message(monkeypatch, job={"context": "@everyone inspect https://example.invalid/?token=bad"})
    observer.process_message(state, observer.DEFAULT_CONFIG, tclk_watch.OFFER_ROOM, record, None, None)
    observer.save_state(state)
    before = observer.state_path().read_bytes()
    control = discord_control.Control({"42"}, "99")
    listed = control.command("42", "/tclk-opportunities", "99")
    detailed = control.command("42", f"/tclk {tclk_watch.opportunities(state)[0]['id']}", "99")
    assert listed["ok"] and detailed["ok"]
    assert "[URL省略]" in detailed["message"] and "@everyone" not in detailed["message"]
    assert "read-only" in detailed["message"] and "not accepted" in detailed["message"]
    assert observer.state_path().read_bytes() == before


def test_runtime_degraded_and_expired_offers_are_not_presented(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    state = observer.default_state(); record = signed_offer_message(monkeypatch)
    observer.process_message(state, observer.DEFAULT_CONFIG, tclk_watch.OFFER_ROOM, record, None, None)
    item = tclk_watch.opportunities(state)[0]; item["expires_ms"] = 0
    assert tclk_watch.opportunities(state) == [] and tclk_watch.offer(state, item["id"]) is None
    observer.save_state(state); before = observer.state_path().read_bytes()
    control = discord_control.Control({"42"}, "99")
    for reason in ("node_unavailable", "pinned_runtime_unavailable", "bridge_unavailable"):
        monkeypatch.setattr(tclk_watch, "runtime_status", lambda reason=reason: {"ready": False, "reason": reason})
        assert "runtime unavailable/degraded" in control.command("42", "/tclk-opportunities", "99")["message"]
    assert observer.state_path().read_bytes() == before


def test_tclk_bridge_scrubs_process_environment(monkeypatch):
    captured = {}

    class Result:
        returncode = 0
        stdout = '{"frame":null}'

    monkeypatch.setenv("SIGN_SEED", "must-not-pass")
    monkeypatch.setenv("TCLK_PAYMENT_KEY", "must-not-pass")
    monkeypatch.setattr(tclk_watch.subprocess, "run", lambda *args, **kwargs: captured.setdefault("env", kwargs["env"]) and Result())
    assert tclk_watch.official_offer("tclk1 {}") is None
    assert "SIGN_SEED" not in captured["env"] and "TCLK_PAYMENT_KEY" not in captured["env"]
