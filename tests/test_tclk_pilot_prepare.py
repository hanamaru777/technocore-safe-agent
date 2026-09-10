from __future__ import annotations

import hashlib
import json

import pytest

from flop_agent import core, tclk_pilot

NOW = 1_800_000_000_000
OFFER_ID = "0x" + "1" * 64
COUNTERPART = "did:key:z6Mk" + "A" * 44
OUR_DID = "did:key:z6Mk" + "B" * 44


def _item():
    frame = "tclk1 " + "x" * 20
    return {
        "id": OFFER_ID,
        "from": COUNTERPART,
        "frame_type": "offer",
        "job_proto": "a2a",
        "job_id": "public-spec-check",
        "rail": "paper",
        "expires_ms": NOW + 900_000,
        "terms_full": "verify public spec full spec: /kv/tclk-job-en/public-spec-check",
        "frame_text": frame,
        "frame_sha256": hashlib.sha256(frame.encode()).hexdigest(),
        "read_only": True,
        "accepted": False,
    }


def _evidence(item):
    spec = "verify public spec document"
    return {
        "offer_id": item["id"],
        "job_id": item["job_id"],
        "frame_sha256": item["frame_sha256"],
        "expires_ms": item["expires_ms"],
        "resolved_at": "2027-01-15T08:00:00+00:00",
        "triage_reason": "human_review_required",
        "full_spec": {
            "namespace": "tclk-job-en",
            "key": item["job_id"],
            "value": spec,
            "sha256": hashlib.sha256(spec.encode()).hexdigest(),
            "bytes": len(spec.encode()),
        },
        "material": None,
        "external_url_present": False,
        "read_count": 1,
        "accepted": False,
    }


def _reader(item, evidence):
    def reader(namespace, key):
        assert (namespace, key) == ("tclk-job-en", item["job_id"])
        return evidence["full_spec"]["value"]

    return reader


def _bridge(calls):
    def bridge(_stage):
        calls["count"] += 1
        line = "tclk1 accept-public-preview"
        return {
            "accept_line": line,
            "accept_sha256": hashlib.sha256(line.encode()).hexdigest(),
            "contract": "0x" + "2" * 64,
            "deal_room": "mb-p-tclk-2222222222222222",
            "lock_material": "0x" + "3" * 64,
        }

    return bridge


def test_stage_is_typed_public_only_and_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)
    item = _item()
    evidence = _evidence(item)
    first = tclk_pilot.stage_offer(item, evidence=evidence, now_ms=NOW)
    second = tclk_pilot.stage_offer(item, evidence=evidence, now_ms=NOW)
    assert first == second
    assert first["task_family"] == "public_verification"
    assert "preimage" not in first
    assert "accept_line" not in first
    assert tclk_pilot.get_stage(first["stage_id"])["frame_sha256"] == item["frame_sha256"]


def test_stage_rejects_external_url_and_changed_evidence_binding(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)
    item = _item()
    evidence = _evidence(item)
    value = "verify public spec https://example.invalid/task"
    evidence["full_spec"].update(value=value, sha256=hashlib.sha256(value.encode()).hexdigest(), bytes=len(value))
    with pytest.raises(tclk_pilot.PilotError, match="external_url_present"):
        tclk_pilot.stage_offer(item, evidence=evidence, now_ms=NOW)

    evidence = _evidence(item)
    evidence["job_id"] = "different-job"
    with pytest.raises(tclk_pilot.PilotError, match="review_evidence_mismatch"):
        tclk_pilot.stage_offer(item, evidence=evidence, now_ms=NOW)


def test_prepare_requires_signer_user(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)
    item = _item()
    stage = tclk_pilot.stage_offer(item, evidence=_evidence(item), now_ms=NOW)
    with pytest.raises(tclk_pilot.PilotError, match="prepare_requires_technocore_signer"):
        tclk_pilot.prepare(stage["stage_id"], now_ms=NOW, username="ubuntu", our_did=OUR_DID)


def test_prepare_persists_private_material_0600_but_returns_public_preview_only(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)
    item = _item()
    evidence = _evidence(item)
    stage = tclk_pilot.stage_offer(item, evidence=evidence, now_ms=NOW)
    monkeypatch.setattr(tclk_pilot, "_official_offer_check", lambda _line, _stage: {})
    calls = {"count": 0}

    preview = tclk_pilot.prepare(
        stage["stage_id"],
        now_ms=NOW,
        reader=_reader(item, evidence),
        username="technocore-signer",
        bridge=_bridge(calls),
        our_did=OUR_DID,
    )
    assert "preimage" not in preview
    assert "lock_material" not in preview
    assert preview["posted"] is False
    private_path = tclk_pilot.private_dir() / f"{stage['stage_id']}.json"
    assert private_path.exists()
    assert private_path.stat().st_mode & 0o777 == 0o600

    again = tclk_pilot.prepare(
        stage["stage_id"],
        now_ms=NOW,
        reader=_reader(item, evidence),
        username="technocore-signer",
        bridge=_bridge(calls),
        our_did=OUR_DID,
    )
    assert again == preview
    assert calls["count"] == 1


def test_prepare_recovers_preview_after_crash_without_minting_again(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)
    item = _item()
    evidence = _evidence(item)
    stage = tclk_pilot.stage_offer(item, evidence=evidence, now_ms=NOW)
    monkeypatch.setattr(tclk_pilot, "_official_offer_check", lambda _line, _stage: {})
    calls = {"count": 0}
    first = tclk_pilot.prepare(
        stage["stage_id"],
        now_ms=NOW,
        reader=_reader(item, evidence),
        username="technocore-signer",
        bridge=_bridge(calls),
        our_did=OUR_DID,
    )
    tclk_pilot.previews_path().unlink()
    recovered = tclk_pilot.prepare(
        stage["stage_id"],
        now_ms=NOW,
        reader=_reader(item, evidence),
        username="technocore-signer",
        bridge=_bridge(calls),
        our_did=OUR_DID,
    )
    assert recovered == first
    assert calls["count"] == 1


def test_prepare_fails_if_fixed_origin_note_hash_changed(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)
    item = _item()
    evidence = _evidence(item)
    stage = tclk_pilot.stage_offer(item, evidence=evidence, now_ms=NOW)
    monkeypatch.setattr(tclk_pilot, "_official_offer_check", lambda _line, _stage: {})
    with pytest.raises(tclk_pilot.PilotError, match="review_evidence_changed"):
        tclk_pilot.prepare(
            stage["stage_id"],
            now_ms=NOW,
            reader=lambda _ns, _key: "verify public spec changed",
            username="technocore-signer",
            bridge=lambda _stage: pytest.fail("bridge must not run"),
            our_did=OUR_DID,
        )


def test_tampered_preview_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)
    item = _item()
    evidence = _evidence(item)
    stage = tclk_pilot.stage_offer(item, evidence=evidence, now_ms=NOW)
    monkeypatch.setattr(tclk_pilot, "_official_offer_check", lambda _line, _stage: {})
    calls = {"count": 0}
    tclk_pilot.prepare(
        stage["stage_id"],
        now_ms=NOW,
        reader=_reader(item, evidence),
        username="technocore-signer",
        bridge=_bridge(calls),
        our_did=OUR_DID,
    )
    store = json.loads(tclk_pilot.previews_path().read_text("utf-8"))
    store["records"][0]["accept_line"] += " changed"
    tclk_pilot.previews_path().write_text(json.dumps(store), "utf-8")
    with pytest.raises(tclk_pilot.PilotError, match="preview_invalid"):
        tclk_pilot.get_preview(stage["stage_id"])


def test_prepare_pending_is_bounded_and_skips_existing_preview(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)
    item = _item()
    evidence = _evidence(item)
    first = tclk_pilot.stage_offer(item, evidence=evidence, now_ms=NOW)
    monkeypatch.setattr(tclk_pilot, "_official_offer_check", lambda _line, _stage: {})
    monkeypatch.setattr(tclk_pilot, "_prepare_did", lambda: OUR_DID)
    monkeypatch.setattr(tclk_pilot, "_prepare_bridge", lambda _stage, our_did: _bridge({"count": 0})(_stage))
    monkeypatch.setattr(core, "read_note", _reader(item, evidence))
    monkeypatch.setattr(tclk_pilot.tclk_note_review, "core", core)

    # prepare_pending uses the module's default reader captured at definition time, so patch prepare
    original_prepare = tclk_pilot.prepare
    monkeypatch.setattr(
        tclk_pilot,
        "prepare",
        lambda stage_id, **kwargs: original_prepare(
            stage_id,
            reader=_reader(item, evidence),
            our_did=OUR_DID,
            bridge=_bridge({"count": 0}),
            **kwargs,
        ),
    )
    rows = tclk_pilot.prepare_pending(now_ms=NOW, username="technocore-signer")
    assert [row["stage_id"] for row in rows] == [first["stage_id"]]
    assert tclk_pilot.prepare_pending(now_ms=NOW, username="technocore-signer") == []


def test_prepare_systemd_worker_has_no_vault_env_and_blocks_metadata():
    root = core.ROOT
    unit = (root / "packaging" / "oracle" / "technocore-safe-agent-tclk-prepare.service").read_text("utf-8")
    timer = (root / "packaging" / "oracle" / "technocore-safe-agent-tclk-prepare.timer").read_text("utf-8")
    assert "User=technocore-signer" in unit
    assert "EnvironmentFile=/etc/technocore-safe-agent/tclk-prepare.env" in unit
    assert "signer.env" not in unit
    assert "IPAddressDeny=169.254.169.254" in unit
    assert "--prepare-pending" in unit
    assert "OnUnitActiveSec=60s" in timer
