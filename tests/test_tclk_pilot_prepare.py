from __future__ import annotations

import hashlib

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


def test_stage_is_typed_public_only_and_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)
    item = _item()
    evidence = _evidence(item)
    first = tclk_pilot.stage_offer(item, evidence=evidence, now_ms=NOW)
    second = tclk_pilot.stage_offer(item, evidence=evidence, now_ms=NOW)
    assert first == second
    assert first["task_family"] == "public_verification"
    assert "secret" not in first
    assert "accept_line" not in first
    assert tclk_pilot.get_stage(first["stage_id"])["frame_sha256"] == item["frame_sha256"]


def test_stage_rejects_external_url_in_resolved_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)
    item = _item()
    evidence = _evidence(item)
    value = "verify public spec https://example.invalid/task"
    evidence["full_spec"].update(value=value, sha256=hashlib.sha256(value.encode()).hexdigest(), bytes=len(value))
    with pytest.raises(tclk_pilot.PilotError, match="external_url_present"):
        tclk_pilot.stage_offer(item, evidence=evidence, now_ms=NOW)


def test_prepare_requires_signer_user(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)
    stage = tclk_pilot.stage_offer(_item(), evidence=_evidence(_item()), now_ms=NOW)
    with pytest.raises(tclk_pilot.PilotError, match="prepare_requires_technocore_signer"):
        tclk_pilot.prepare(stage["stage_id"], now_ms=NOW, username="ubuntu")


def test_prepare_persists_secret_0600_but_returns_public_preview_only(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "STATE", tmp_path)
    item = _item()
    evidence = _evidence(item)
    stage = tclk_pilot.stage_offer(item, evidence=evidence, now_ms=NOW)
    monkeypatch.setattr(tclk_pilot, "_official_offer_check", lambda _line, _stage: {})
    monkeypatch.setenv("TECHNOCORE_SIGNER_EXPECTED_DID", OUR_DID)

    def reader(namespace, key):
        assert (namespace, key) == ("tclk-job-en", item["job_id"])
        return evidence["full_spec"]["value"]

    calls = {"count": 0}
    def bridge(_stage):
        calls["count"] += 1
        line = "tclk1 accept-public-preview"
        return {
            "accept_line": line,
            "accept_sha256": hashlib.sha256(line.encode()).hexdigest(),
            "contract": "0x" + "2" * 64,
            "deal_room": "mb-p-tclk-2222222222222222",
            "secret": "0x" + "3" * 64,
        }

    preview = tclk_pilot.prepare(stage["stage_id"], now_ms=NOW, reader=reader, username="technocore-signer", bridge=bridge)
    assert "secret" not in preview
    assert preview["posted"] is False
    secret_path = tclk_pilot.secret_dir() / f"{stage['stage_id']}.json"
    assert secret_path.exists()
    assert secret_path.stat().st_mode & 0o777 == 0o600

    again = tclk_pilot.prepare(stage["stage_id"], now_ms=NOW, reader=reader, username="technocore-signer", bridge=bridge)
    assert again == preview
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
        )
