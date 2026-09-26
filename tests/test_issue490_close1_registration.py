import contextlib
import copy
import hashlib
import re
from pathlib import Path

import pytest

from flop_agent import close1_registration_once as registration

HELPER = Path("packaging/oracle/issue490-close1-registration-v1.sh")
MODULE = Path("src/flop_agent/close1_registration_once.py")


@contextlib.contextmanager
def _lock():
    yield


class _Response:
    def __init__(self, row):
        self._row = row

    def raise_for_status(self):
        return None

    def json(self):
        return {"posted": self._row}


def _install_safe_harness(monkeypatch):
    holder = {"value": None}
    monkeypatch.setattr(registration, "registration_lock", _lock)
    monkeypatch.setattr(registration, "require_identity", lambda: None)
    monkeypatch.setattr(registration, "require_window", lambda: None)
    monkeypatch.setattr(registration, "require_safety", lambda: None)
    monkeypatch.setattr(
        registration,
        "load",
        lambda: copy.deepcopy(holder["value"]),
    )
    monkeypatch.setattr(
        registration,
        "save",
        lambda value: holder.__setitem__("value", copy.deepcopy(value)),
    )
    monkeypatch.setattr(registration.core, "make_nonce", lambda room, did: "1791100000000")
    monkeypatch.setattr(
        registration.oracle_signer,
        "with_vault_seed",
        lambda operation: operation(),
    )
    monkeypatch.setattr(
        registration.core,
        "invoke_signer",
        lambda *args: [registration.DID, "A" * 86],
    )
    monkeypatch.setattr(registration, "verify_signed_record", lambda room, row: None)
    return holder


def test_close1_binding_is_exact_and_has_no_runtime_parameters():
    assert registration.ROOM == "close1"
    assert registration.DID == "did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
    assert registration.REGISTRATION == {
        "key": registration.DID,
        "season": "close-1",
        "t": "owner",
    }
    assert registration.render() == (
        '{"key":"did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB",'
        '"season":"close-1","t":"owner"}'
    )


def test_success_posts_once_and_persists_exact_signed_receipt(monkeypatch):
    holder = _install_safe_harness(monkeypatch)
    monkeypatch.setattr(registration, "find_existing_record", lambda **kwargs: None)
    monkeypatch.setattr(registration, "readback", lambda row: True)

    calls = []

    def post(url, *, json, timeout):
        calls.append((url, copy.deepcopy(json), timeout))
        row = {
            "from": registration.DID,
            "nonce": json["nonce"],
            "text": registration.TEXT,
            "sig": json["sig"],
            "seq": 321,
            "ts": "2026-09-26T02:30:00.000000Z",
        }
        return _Response(row)

    monkeypatch.setattr(registration.core.httpx, "post", post)

    result = registration.run_once()

    assert result["action"] == "posted"
    assert result["post_attempted"] is True
    assert result["readback"] is True
    assert len(calls) == 1
    url, payload, timeout = calls[0]
    assert url == f"{registration.core.BASE_URL}/r/close1?format=json"
    assert payload == {
        "did": registration.DID,
        "nonce": "1791100000000",
        "text": registration.TEXT,
        "sig": "A" * 86,
    }
    assert timeout == 20
    assert holder["value"]["state"] == "posted"
    assert holder["value"]["seq"] == 321


def test_ambiguous_post_never_retries(monkeypatch):
    holder = _install_safe_harness(monkeypatch)
    monkeypatch.setattr(registration, "find_existing_record", lambda **kwargs: None)

    calls = {"post": 0}

    def post(*args, **kwargs):
        calls["post"] += 1
        raise RuntimeError("simulated transport ambiguity")

    monkeypatch.setattr(registration.core.httpx, "post", post)

    with pytest.raises(registration.RegistrationError) as captured:
        registration.run_once()

    assert captured.value.code == "submission_unknown"
    assert captured.value.post_attempted is True
    assert calls["post"] == 1
    assert holder["value"]["state"] == "ambiguous"


def test_failed_safety_gate_never_signs_or_posts(monkeypatch):
    monkeypatch.setattr(registration, "registration_lock", _lock)
    monkeypatch.setattr(registration, "require_identity", lambda: None)
    monkeypatch.setattr(registration, "require_window", lambda: None)

    def stop():
        raise registration.RegistrationError("observer_health_not_ok")

    monkeypatch.setattr(registration, "require_safety", stop)

    signed = {"called": False}
    posted = {"called": False}

    def sign(operation):
        signed["called"] = True
        return operation()

    def post(*args, **kwargs):
        posted["called"] = True
        raise AssertionError("must not post")

    monkeypatch.setattr(registration.oracle_signer, "with_vault_seed", sign)
    monkeypatch.setattr(registration.core.httpx, "post", post)

    with pytest.raises(registration.RegistrationError) as captured:
        registration.run_once()

    assert captured.value.code == "observer_health_not_ok"
    assert signed["called"] is False
    assert posted["called"] is False


def test_prepared_state_is_not_reused_for_post(monkeypatch):
    _install_safe_harness(monkeypatch)
    value = registration.initial_state()
    value.update(state="prepared", nonce="1791100000000")
    monkeypatch.setattr(registration, "load", lambda: copy.deepcopy(value))

    posted = {"called": False}
    monkeypatch.setattr(
        registration.core.httpx,
        "post",
        lambda *args, **kwargs: posted.__setitem__("called", True),
    )

    with pytest.raises(registration.RegistrationError) as captured:
        registration.run_once()

    assert captured.value.code == "prepared_state_requires_new_task"
    assert posted["called"] is False


def test_helper_pins_production_and_module_bytes_and_has_no_mutating_ops():
    source = HELPER.read_text("utf-8")
    module_bytes = MODULE.read_bytes()

    assert "EXPECTED_HEAD=9baa91be7267b22143c33a06df3c67e1074dba0d" in source
    assert "RES_PID=2462149" in source
    assert "CAP_PID=2462148" in source
    assert "SIG_PID=2462068" in source
    assert "DIS_PID=2462020" in source
    assert "CORE_E=124" in source and "CORE_M=5651120" in source
    assert "BRIDGE_E=7" in source and "BRIDGE_M=567965" in source
    assert "CLOSE1_REGISTER_HELPER=INVOKING_APPROVED_BINDING_ACTION" in source
    assert "raw_seed_env_forbidden" in source

    a = re.search(r"^MODULE_SHA_A=([0-9a-f]{32})$", source, re.M)
    b = re.search(r"^MODULE_SHA_B=([0-9a-f]{32})$", source, re.M)
    assert a and b
    assert hashlib.sha256(module_bytes).hexdigest() == a.group(1) + b.group(1)

    for pattern in (
        r"systemctl\s+(?:restart|start|stop|enable|disable|daemon-reload)\b",
        r"git_owner\s+(?:fetch|merge|pull|checkout|reset)\b",
        r"\bsqlite3\b",
        r"\bjournalctl\b",
    ):
        assert re.search(pattern, source) is None


def test_module_has_no_trade_or_generic_message_binding_surface():
    source = MODULE.read_text("utf-8")
    assert "argparse" not in source
    assert "sys.argv[1" not in source
    assert 'ROOM = "close1"' in source
    assert 'REGISTRATION = {"key": DID, "season": "close-1", "t": "owner"}' in source
    assert 'core.invoke_signer("say", ROOM, value["nonce"], render())' in source
    assert "/trade" not in source
