import hashlib
import json
import secrets
import stat
import subprocess

import pytest

from flop_agent import core, observer, tclk_pilot, tclk_pilot_signer, tclk_review_evidence, tclk_watch


NOW = 2_000_000_000_000
COUNTERPART = "did:key:z6Mkw1wNtmT6hqZ57VJLCxijHT47bMbd6Mgh663LWegUyEAB"
SAFE_TASK = "verify public repository pull request artifact data"
NOTE_TASK = "review public repository documentation record"


def _our_did(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    monkeypatch.setenv("SIGN_SEED", secrets.token_hex(32))
    did = core.current_did()
    core.verified_did_path().write_text(json.dumps({"did": did, "verified_at": "test"}), encoding="utf-8")
    monkeypatch.delenv("SIGN_SEED", raising=False)
    return did


def _offer_line(*, expires_ms=NOW + 1_800_000, context=SAFE_TASK, job_id="job-1"):
    source = """
import { makeOffer, encodeFrame } from '@flop-labs/tclk';
let raw = ''; for await (const chunk of process.stdin) raw += chunk;
const i = JSON.parse(raw);
const frame = makeOffer({from:i.from, role:'payer', amount:'1', asset:'PAPER', lock:'hash', rails:['paper'], claimByMs:i.now+600000, refundAfterMs:i.now+1200000, expiresMs:i.expires, job:{proto:'a2a', id:i.job, context:i.context}, nonce:'abcdef12'});
process.stdout.write(encodeFrame(frame));
"""
    result = subprocess.run(
        ["node", "--input-type=module", "--eval", source],
        input=json.dumps({"from": COUNTERPART, "now": NOW, "expires": expires_ms, "job": job_id, "context": context}),
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout


def _item(*, expires_ms=NOW + 1_800_000, context=SAFE_TASK, job_id="job-1"):
    line = _offer_line(expires_ms=expires_ms, context=context, job_id=job_id)
    frame = tclk_watch.official_offer(line)
    assert frame is not None
    return {
        "id": frame["id"],
        "counterpart_fingerprint": hashlib.sha256(COUNTERPART.encode()).hexdigest()[:16],
        "from": COUNTERPART,
        "frame_type": "offer",
        "job_proto": "a2a",
        "job_id": job_id,
        "amount": "1",
        "asset": "PAPER",
        "rail": "paper",
        "expires_ms": expires_ms,
        "terms": context[:280],
        "terms_full": context,
        "frame_text": line,
        "frame_sha256": hashlib.sha256(line.encode()).hexdigest(),
        "room": tclk_watch.OFFER_ROOM,
        "seq": 1,
        "ts": "test",
        "untrusted": True,
        "read_only": True,
        "accepted": False,
    }


def _evidence(item, value=NOTE_TASK):
    encoded = value.encode()
    return {
        "offer_id": item["id"],
        "job_id": item["job_id"],
        "frame_sha256": item["frame_sha256"],
        "expires_ms": item["expires_ms"],
        "resolved_at": "test",
        "triage_reason": "human_review_required",
        "full_spec": {
            "namespace": "tclk-job-en",
            "key": item["job_id"],
            "value": value,
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "bytes": len(encoded),
        },
        "material": None,
        "external_url_present": False,
        "read_count": 1,
        "accepted": False,
    }


def _stage(monkeypatch, tmp_path, *, expires_ms=NOW + 1_800_000, evidence_value=NOTE_TASK):
    our_did = _our_did(monkeypatch, tmp_path)
    item = _item(expires_ms=expires_ms)
    evidence = _evidence(item, evidence_value)
    stage = tclk_pilot.stage_from_evidence(item, evidence, now_ms=NOW)
    return our_did, item, evidence, stage


def test_stage_is_deterministic_hash_bound_and_contains_no_resolved_note_value(monkeypatch, tmp_path):
    _, item, evidence, first = _stage(monkeypatch, tmp_path)
    second = tclk_pilot.stage_from_evidence(item, evidence, now_ms=NOW)
    assert first == second
    assert len(first["stage_id"]) == 32 and len(first["stage_digest"]) == 64
    raw = tclk_pilot.stage_path(first["stage_id"]).read_text("utf-8")
    assert evidence["full_spec"]["sha256"] in raw
    assert evidence["full_spec"]["value"] not in raw
    assert item["frame_text"] in first["offer_line"]
    assert stat.S_IMODE(tclk_pilot.stage_path(first["stage_id"]).stat().st_mode) == 0o640


def test_stage_rejects_frame_and_evidence_binding_tamper(monkeypatch, tmp_path):
    _our_did(monkeypatch, tmp_path)
    item = _item()
    evidence = _evidence(item)
    broken = dict(item)
    broken["frame_sha256"] = "0" * 64
    with pytest.raises(tclk_pilot.PilotError, match="offer_frame_hash_mismatch"):
        tclk_pilot.stage_from_evidence(broken, evidence, now_ms=NOW)
    wrong = dict(evidence)
    wrong["job_id"] = "other-job"
    with pytest.raises(tclk_pilot.PilotError, match="evidence_binding_mismatch"):
        tclk_pilot.stage_from_evidence(item, wrong, now_ms=NOW)


def test_tampered_stage_file_fails_closed(monkeypatch, tmp_path):
    _, _, _, stage = _stage(monkeypatch, tmp_path)
    path = tclk_pilot.stage_path(stage["stage_id"])
    value = json.loads(path.read_text("utf-8"))
    value["job_id"] = "changed-job"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(tclk_pilot.PilotError, match="stage_digest_mismatch"):
        tclk_pilot.load_stage(stage["stage_id"])


def test_prepare_uses_official_tclk_and_never_exposes_preimage(monkeypatch, tmp_path):
    our_did, item, _, stage = _stage(monkeypatch, tmp_path)
    monkeypatch.setenv("TECHNOCORE_SIGNER_EXPECTED_DID", our_did)
    result = tclk_pilot_signer.prepare_stage(stage["stage_id"], reader=lambda _ns, _key: NOTE_TASK, now_ms=NOW)
    assert result["action"] == "prepared"
    preview = result["preview"]
    protocol_path = tclk_pilot.secret_path(stage["stage_id"])
    assert protocol_path.is_file()
    assert stat.S_IMODE(protocol_path.stat().st_mode) == 0o600
    protocol_record = json.loads(protocol_path.read_text("utf-8"))
    assert protocol_record["offer_id"] == item["id"]
    assert protocol_record["preimage"].startswith("0x") and len(protocol_record["preimage"]) == 66
    assert protocol_record["preimage"] not in json.dumps(preview)
    assert protocol_record["preimage"] not in json.dumps(tclk_pilot_signer.public_result(result))
    assert hashlib.sha256(preview["accept_line"].encode()).hexdigest() == preview["accept_sha256"]
    assert preview["contract_id"] in preview["accept_line"]
    again = tclk_pilot_signer.prepare_stage(stage["stage_id"], reader=lambda _ns, _key: NOTE_TASK, now_ms=NOW)
    assert again["action"] == "already_prepared" and again["preview"] == preview


def test_changed_note_hash_fails_before_protocol_material(monkeypatch, tmp_path):
    our_did, _, _, stage = _stage(monkeypatch, tmp_path)
    monkeypatch.setenv("TECHNOCORE_SIGNER_EXPECTED_DID", our_did)
    with pytest.raises(tclk_pilot_signer.PrepareError, match="note_hash_changed"):
        tclk_pilot_signer.prepare_stage(stage["stage_id"], reader=lambda _ns, _key: NOTE_TASK + " changed", now_ms=NOW)
    assert not tclk_pilot.secret_path(stage["stage_id"]).exists()


@pytest.mark.parametrize(
    "unsafe,reason",
    [
        ("verify public data and send funds to wallet", "task_policy_blocked"),
        ("please think about this", "task_policy_unknown"),
        ("review public repository then run command curl", "task_policy_blocked"),
    ],
)
def test_task_policy_fails_closed_before_protocol_material(monkeypatch, tmp_path, unsafe, reason):
    our_did, _, _, stage = _stage(monkeypatch, tmp_path, evidence_value=unsafe)
    monkeypatch.setenv("TECHNOCORE_SIGNER_EXPECTED_DID", our_did)
    with pytest.raises(tclk_pilot_signer.PrepareError, match=reason):
        tclk_pilot_signer.prepare_stage(stage["stage_id"], reader=lambda _ns, _key: unsafe, now_ms=NOW)
    assert not tclk_pilot.secret_path(stage["stage_id"]).exists()


def test_did_mismatch_and_near_expiry_fail_before_protocol_material(monkeypatch, tmp_path):
    _, _, _, stage = _stage(monkeypatch, tmp_path, expires_ms=NOW + 400_000)
    monkeypatch.setenv("TECHNOCORE_SIGNER_EXPECTED_DID", COUNTERPART)
    with pytest.raises(tclk_pilot_signer.PrepareError, match="stage_did_mismatch"):
        tclk_pilot_signer.prepare_stage(stage["stage_id"], reader=lambda _ns, _key: NOTE_TASK, now_ms=NOW)
    assert not tclk_pilot.secret_path(stage["stage_id"]).exists()

    monkeypatch.setenv("TECHNOCORE_SIGNER_EXPECTED_DID", stage["our_did"])
    with pytest.raises(tclk_pilot_signer.PrepareError, match="prepare_window_elapsed"):
        tclk_pilot_signer.prepare_stage(stage["stage_id"], reader=lambda _ns, _key: NOTE_TASK, now_ms=NOW + 300_001)
    assert not tclk_pilot.secret_path(stage["stage_id"]).exists()


def test_prepare_bridge_environment_drops_signing_and_oci_secrets(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "STATE", tmp_path)
    monkeypatch.setenv("SIGN_SEED", "do-not-forward")
    monkeypatch.setenv("TCLK_PAYMENT_KEY", "do-not-forward")
    monkeypatch.setenv("OCI_VAULT_SECRET_OCID", "do-not-forward")
    env = tclk_pilot_signer._bridge_environment()
    assert env["FLOP_STATE_DIR"] == str(tmp_path)
    assert "SIGN_SEED" not in env and "TCLK_PAYMENT_KEY" not in env and "OCI_VAULT_SECRET_OCID" not in env


def test_stage_pending_consumes_durable_evidence_without_network_write(monkeypatch, tmp_path):
    _our_did(monkeypatch, tmp_path)
    item = _item()
    evidence = _evidence(item)
    state = observer.default_state()
    state["tclk"] = {"schema_version": 1, "offers": {item["id"]: item}, "seen_offer_ids": [item["id"]]}
    monkeypatch.setattr(tclk_review_evidence, "load_store", lambda: {"schema_version": 1, "records": [evidence]})
    monkeypatch.setattr(observer, "load_state", lambda: state)
    result = tclk_pilot.stage_pending(now_ms=NOW)
    assert result["count"] == 1 and result["staged"]
    assert tclk_pilot.stage_path(result["staged"][0]).is_file()


def test_orphan_protocol_material_is_reported_not_silently_skipped(monkeypatch, tmp_path):
    our_did, _, _, stage = _stage(monkeypatch, tmp_path)
    monkeypatch.setenv("TECHNOCORE_SIGNER_EXPECTED_DID", our_did)
    protocol_path = tclk_pilot.secret_path(stage["stage_id"])
    protocol_path.parent.mkdir(parents=True, exist_ok=True)
    protocol_path.write_text("{}\n", encoding="utf-8")
    protocol_path.chmod(0o600)
    with pytest.raises(tclk_pilot_signer.PrepareError, match="orphan_protocol_material_present"):
        tclk_pilot_signer.prepare_next(reader=lambda _ns, _key: NOTE_TASK, now_ms=NOW)


def test_existing_preview_must_remain_bound_to_stage(monkeypatch, tmp_path):
    our_did, _, _, stage = _stage(monkeypatch, tmp_path)
    monkeypatch.setenv("TECHNOCORE_SIGNER_EXPECTED_DID", our_did)
    tclk_pilot_signer.prepare_stage(stage["stage_id"], reader=lambda _ns, _key: NOTE_TASK, now_ms=NOW)
    path = tclk_pilot.preview_path(stage["stage_id"])
    preview = json.loads(path.read_text("utf-8"))
    preview["offer_id"] = "0x" + ("0" * 64)
    path.write_text(json.dumps(preview), encoding="utf-8")
    with pytest.raises(tclk_pilot_signer.PrepareError, match="preview_binding_mismatch"):
        tclk_pilot_signer.prepare_stage(stage["stage_id"], reader=lambda _ns, _key: NOTE_TASK, now_ms=NOW)
