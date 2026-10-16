"""R861: fully synthetic offline archive metadata contract tests."""
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "packaging/archive/retirement_archive_contract.py"

def module():
    spec = importlib.util.spec_from_file_location("flop_r861", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def fixtures(m):
    capture = {
        "kind": "preliminary_capture_only", "source_commit": m.SOURCE,
        "capture_unit_remained_inactive": True,
        "signer_autopilot_and_nonce_not_archived": True,
        "off_host_restored": False,
        "sqlite_integrity_off_host_pending": True,
        "files": [
            {"source_relative": src, "source_size_at_preflight": 2000,
             "archive_file": name, "archive_size": 1600, "backup_steps": 1}
            for src, name, _ in m.DBS
        ],
    }
    state = {"source_commit":m.SOURCE,
             "files":[{"path": p, "type": "regular", "size": 100}
                      for p in sorted(m.REQUIRED)]}
    return capture, state

def add(state, *names):
    for name in names:
        state["files"].append({"path": name, "type": "regular", "size": 1})

def test_real_preliminary_names_map_exactly_to_offhost_canonical():
    m = module()
    captures, states = m.plan(*fixtures(m))
    assert captures == [
        ("capture-0.sqlite3", "capture/lobby-capture.sqlite3"),
        ("capture-1.sqlite3", "capture/lobby-capture-service.sqlite3"),
    ]
    assert "state/autopilot/autopilot-audit.jsonl" in dict(states)
    assert len(states) == len(m.REQUIRED)

def test_missing_outbox_nonce_audit_and_config_all_stop():
    m = module()
    for missing in ("nonces.json", "observer-safety.json",
                    "autopilot/autopilot-audit.jsonl",
                    "observer/observer-config.json", "signer/oracle-signer-receipts.json"):
        c, s = fixtures(m)
        s["files"] = [r for r in s["files"] if r["path"] != missing]
        with pytest.raises(m.Stop, match="REQUIRED_STATE_MISSING"):
            m.plan(c, s)

def test_rotated_audits_preserved_only_if_contiguous():
    m = module()
    c, s = fixtures(m)
    add(s, "autopilot/autopilot-audit.jsonl.1",
        "autopilot/autopilot-audit.jsonl.2")
    _, states = m.plan(c, s)
    assert "state/autopilot/autopilot-audit.jsonl.2" in dict(states)
    s["files"] = [row for row in s["files"] if not row["path"].endswith(".1")]
    with pytest.raises(m.Stop, match="AUDIT_ROTATION_GAP"):
        m.plan(c, s)

def test_legacy_and_unclassified_paths_fail_closed():
    m = module()
    for path, why in [
        ("observer/autopilot-outbox.json", "LEGACY_AUTOPILOT"),
        ("close1/unchecked.json", "UNCLASSIFIED_STATE"),
        ("public-proofs/unclassified.bin", "UNCLASSIFIED_STATE"),
        ("signer.env", "UNCLASSIFIED_STATE"),
    ]:
        c, s = fixtures(m)
        add(s, path)
        with pytest.raises(m.Stop, match=why):
            m.plan(c, s)

def test_capture_origins_never_directly_copied_with_sidecars():
    m = module()
    c, s = fixtures(m)
    add(s, *[x[0] for x in m.DBS],
        "observer/lobby-capture.sqlite3-wal",
        "observer/lobby-capture.sqlite3-shm")
    cap, rows = m.plan(c, s)
    assert len(cap) == 2 and len(rows) == len(m.REQUIRED)

def test_proof_plan_and_cursors_covered_from_inventory():
    m = module()
    c, s = fixtures(m)
    add(s, "proof-plans/0123456789abcdef.json",
        "cursor-public-room.json")
    _, rows = m.plan(c, s)
    assert "state/proof-plans/0123456789abcdef.json" in dict(rows)
    assert "state/cursor-public-room.json" in dict(rows)

def test_reversed_capture_mapping_rejected():
    m = module()
    c, s = fixtures(m)
    c["files"].reverse()
    with pytest.raises(m.Stop, match="CAPTURE_MAPPING_MISMATCH"):
        m.plan(c, s)

def test_unsafe_traversal_and_symlink_file_type_rejected():
    m = module()
    for path, ty, why in [
        ("../etc/shadow", "regular", "PATH_UNSAFE"),
        ("signer/signer-health.json", "symlink", "STATE_FILE_TYPE_OR_SIZE"),
    ]:
        c, s = fixtures(m)
        if path.startswith(".."):
            add(s, path)
        else:
            for row in s["files"]:
                if row["path"] == path:
                    row["type"] = ty
        with pytest.raises(m.Stop, match=why):
            m.plan(c, s)

def test_duplicate_empty_or_negative_size_rejected():
    m = module()
    c, s = fixtures(m)
    add(s, "nonces.json")
    with pytest.raises(m.Stop, match="STATE_DUPLICATE_PATH"):
        m.plan(c, s)
    c, s = fixtures(m)
    s["files"][0]["size"] = -1
    with pytest.raises(m.Stop, match="STATE_FILE_TYPE_OR_SIZE"):
        m.plan(c, s)

def test_invalid_capture_flags_and_source_commit():
    m = module()
    c, s = fixtures(m)
    c["off_host_restored"] = True
    with pytest.raises(m.Stop, match="CAPTURE_PROVENANCE_INVALID"):
        m.plan(c, s)
    c, s = fixtures(m)
    s["source_commit"] = "0" * 40
    with pytest.raises(m.Stop, match="STATE_INVENTORY_SCHEMA"):
        m.plan(c, s)

def test_source_never_accesses_live_data_network_or_mutates():
    source = SCRIPT.read_text()
    compile(source, str(SCRIPT), "exec")
    for token in ("import sqlite3", "import subprocess", "import requests",
                  "os.system(", "urllib", "shutil.copy", "os.remove(",
                  "Path.write_bytes", "Path.write_text", "systemctl",
                  "BucketCreate", "PutObject"):
        assert token not in source
    assert "FLOP_R861_ORACLE_DELETION_NOT_AUTHORIZED" in source


def test_close1_trade_attempt_receipt_and_account_are_preserved():
    m = module()
    c, state = fixtures(m)
    token = "a" * 64
    add(state, "close1/close1-own-account.json",
        "close1/close1-autonomous-stage.json",
        "observer/close1-standalone-watch.json",
        "observer/resident-control.json",
        "observer/resident-heartbeat.json",
        "signer/close1-approved-trade.json",
        "signer/close1-attempt-" + token + ".json",
        "signer/close1-receipt-" + token + ".json",
        "signer/close1-approved-trade.lock")
    _, files = m.plan(c, state)
    names = dict(files)
    assert "state/close1/close1-own-account.json" in names
    assert "state/signer/close1-attempt-" + token + ".json" in names
    assert "state/signer/close1-receipt-" + token + ".json" in names
    assert "state/signer/close1-approved-trade.lock" not in names


def test_completed_close1_registration_is_identity_history_not_a_trade():
    m = module()
    c, state = fixtures(m)
    add(state, "signer/close1-registration.json",
        "signer/close1-registration.lock")
    _, archive = m.plan(c, state)
    files = dict(archive)
    assert "state/signer/close1-registration.json" in files
    assert "state/signer/close1-registration.lock" not in files
    assert "state/close1/close1-own-account.json" not in files
    # Unrelated Close1 trading artifacts still require their own ledger.
    add(state, "signer/close1-approved-batch.json")
    with pytest.raises(m.Stop, match="FINANCE_ACCOUNT_LEDGER_MISSING"):
        m.plan(c, state)


def test_financial_attempt_without_receipt_is_never_a_clear_cutover():
    m = module()
    c, state = fixtures(m)
    add(state, "close1/close1-own-account.json",
        "signer/close1-attempt-" + "c" * 64 + ".json")
    with pytest.raises(m.Stop, match="FINANCE_AMBIGUOUS_ATTEMPT_STOP"):
        m.plan(c, state)


def test_financial_receipt_without_matching_attempt_is_rejected():
    m = module()
    c, state = fixtures(m)
    add(state, "close1/close1-own-account.json",
        "signer/close1-receipt-" + "d" * 64 + ".json")
    with pytest.raises(m.Stop, match="FINANCE_RECEIPT_WITHOUT_ATTEMPT"):
        m.plan(c, state)


def test_trade_approval_without_ledger_is_rejected():
    m = module()
    c, state = fixtures(m)
    add(state, "signer/close1-approved-batch.json")
    with pytest.raises(m.Stop, match="FINANCE_ACCOUNT_LEDGER_MISSING"):
        m.plan(c, state)


def test_unclassified_finance_filename_stays_fail_closed():
    m = module()
    c, state = fixtures(m)
    add(state, "close1/new-financial-stage.json")
    with pytest.raises(m.Stop, match="UNCLASSIFIED_STATE_FILE_STOP"):
        m.plan(c, state)

def test_main_accepts_metadata_offline_only(tmp_path, monkeypatch, capsys):
    m = module()
    c, s = fixtures(m)
    a = tmp_path / "cap.json"
    b = tmp_path / "inventory.json"
    a.write_text(json.dumps(c))
    b.write_text(json.dumps(s))
    monkeypatch.setattr(m.sys, "argv",
                        ["script", "--capture-metadata", str(a),
                         "--state-inventory", str(b)])
    m.main()
    output = capsys.readouterr().out
    assert "FLOP_R861_OFFLINE_METADATA_PLAN_PASS" in output
    assert "FLOP_R861_NO_ARCHIVE_NO_UPLOAD_NO_WRITER_EPOCH_PROOF" in output


def test_tclk_private_hashlock_and_reveal_files_are_retained_offline():
    m = module()
    c, state = fixtures(m)
    stage = "a" * 32
    add(state,
        "autopilot/tclk-pilot/stages/" + stage + ".json",
        "autopilot/tclk-pilot/previews/" + stage + ".json",
        "autopilot/tclk-pilot/locks/" + stage + ".json",
        "autopilot/tclk-pilot/work/" + stage + ".json",
        "autopilot/tclk-pilot/reveal-previews/" + stage + ".json",
        "autopilot/tclk-pilot/terminal/" + stage + ".json",
        "signer/tclk-pilot-secrets/" + stage + ".json",
        "signer/tclk-pilot-approvals/" + stage + ".json",
        "signer/tclk-pilot-accepts/" + stage + ".json",
        "signer/tclk-pilot-reveals/" + stage + ".json",
        "signer/tclk-pilot-reveal-approvals/" + stage + ".json",
        "signer/tclk-pilot-reveal-publishes/" + stage + ".json")
    _, retained = m.plan(c, state)
    names = dict(retained)
    assert "state/signer/tclk-pilot-secrets/" + stage + ".json" in names
    assert "state/signer/tclk-pilot-reveals/" + stage + ".json" in names
    assert "state/autopilot/tclk-pilot/stages/" + stage + ".json" in names
    assert len(retained) == len(m.REQUIRED) + 12


def test_tclk_public_accept_without_private_preimage_fails_closed():
    m = module()
    c, state = fixtures(m)
    stage = "b" * 32
    add(state, "autopilot/tclk-pilot/stages/" + stage + ".json",
        "autopilot/tclk-pilot/previews/" + stage + ".json")
    with pytest.raises(m.Stop, match="TCLK_SECRET_CUSTODY_MISSING"):
        m.plan(c, state)


def test_tclk_unpaired_private_secret_and_reveal_fail_closed():
    m = module()
    for private_path in (
        "signer/tclk-pilot-secrets/",
        "signer/tclk-pilot-reveals/",
    ):
        c, state = fixtures(m)
        add(state, private_path + "c" * 32 + ".json")
        with pytest.raises(m.Stop, match="TCLK_STAGE_CUSTODY_MISSING"):
            m.plan(c, state)


def test_tclk_empty_private_secret_and_unexpected_name_fail_closed():
    m = module()
    stage = "d" * 32
    c, state = fixtures(m)
    add(state, "autopilot/tclk-pilot/stages/" + stage + ".json",
        "signer/tclk-pilot-secrets/" + stage + ".json")
    for row in state["files"]:
        if row["path"].startswith("signer/tclk-pilot-secrets/"):
            row["size"] = 0
    with pytest.raises(m.Stop, match="TCLK_EMPTY_STATE_STOP"):
        m.plan(c, state)
    c, state = fixtures(m)
    add(state, "signer/tclk-pilot-secrets/unchecked.json")
    with pytest.raises(m.Stop, match="UNCLASSIFIED_STATE_FILE_STOP"):
        m.plan(c, state)
    c, state = fixtures(m)
    add(state, "signer/tclk-pilot-unknown/" + stage + ".json")
    with pytest.raises(m.Stop, match="UNCLASSIFIED_STATE_FILE_STOP"):
        m.plan(c, state)


def test_tclk_stage_only_does_not_invent_a_private_preimage():
    m = module()
    c, state = fixtures(m)
    stage = "e" * 32
    add(state, "autopilot/tclk-pilot/stages/" + stage + ".json")
    _, retained = m.plan(c, state)
    assert "state/autopilot/tclk-pilot/stages/" + stage + ".json" in dict(retained)
    assert "state/signer/tclk-pilot-secrets/" + stage + ".json" not in dict(retained)


def test_r942_real_host_scale_would_stop_without_verified_reduction():
    """R938 measured 3,017 files; never silently increase 512-record cap."""
    m = module()
    capture, state = fixtures(m)
    assert m.MAX_PATHS == 512
    for index in range(513):
        state["files"].append(
            {"path": f"cursor-r942{index:05d}.json",
             "type": "regular", "size": 1})
    with pytest.raises(m.Stop, match="STATE_INVENTORY_COUNT"):
        m.plan(capture, state)


def test_r942_no_allowing_real_unknown_giant_log_by_lifting_max_file():
    """The unknown 5.16GB log is NOT normal bounded autopilot audit."""
    m = module()
    capture, state = fixtures(m)
    assert m.MAX_FILE == 3 * 1024**3
    target = next(row for row in state["files"]
                  if row["path"] == "autopilot/autopilot-audit.jsonl")
    target["size"] = 5166537629
    with pytest.raises(m.Stop, match="STATE_FILE_TYPE_OR_SIZE"):
        m.plan(capture, state)


def test_r942_total_capacity_limit_still_blocks_large_mixed_state():
    """A selected, enumerated state total >6GiB is not certified minimum."""
    m = module()
    capture, state = fixtures(m)
    assert m.MAX_STATE == 6 * 1024**3
    for path in ("nonces.json", "observer/observer-state.json",
                 "autopilot/autopilot-audit.jsonl"):
        row = next(row for row in state["files"] if row["path"] == path)
        row["size"] = (5 * 1024**3) // 2
    with pytest.raises(m.Stop, match="STATE_TOTAL_EXCEEDED"):
        m.plan(capture, state)


def test_r942_tmp_cache_and_unknown_autopilot_log_not_implicitly_skipped():
    """Rebuildable-looking is not equivalent to proven safe-to-exclude."""
    m = module()
    unknown_paths = (
        "observer/.observer-state.json.r942.tmp",
        "observer/any-unreviewed.tmp",
        "signer/uv-cache/potential-runtime-dependency.bin",
        "autopilot/unreviewed-large.log",
    )
    for path in unknown_paths:
        capture, state = fixtures(m)
        state["files"].append({"path": path, "type": "regular", "size": 2})
        with pytest.raises(m.Stop, match="UNCLASSIFIED_STATE_FILE_STOP"):
            m.plan(capture, state)


def test_r945_pinned_original_radar_challenge_and_public_proof_files_retained():
    """Offline source-path parity: exact approved records stay in manifest."""
    m = module()
    c, s = fixtures(m)
    rows = (
        "airdrop-radar/state.json",
        "airdrop-radar/events.jsonl",
        "airdrop-radar/current-snapshot.json",
        "airdrop-radar/event-index.json",
        "airdrop-radar/precontest-supervisor.json",
        "airdrop-radar/precontest-candidates.json",
        "airdrop-radar/challenges/contest_2026/spec.json",
        "airdrop-radar/challenges/contest_2026/requests.json",
        "airdrop-radar/challenges/contest_2026/artifacts.json",
        "airdrop-radar/challenges/contest_2026/precontest-control-path-proof.json",
        "airdrop-radar/challenges/contest_2026/precontest-readiness-sources.json",
        "airdrop-radar/challenge-candidate-reviews/challenge_repo.json",
        "public-proofs/proof-" + "b" * 16 + "-20261017T080200Z.json",
    )
    add(s, *rows)
    _, items = m.plan(c, s)
    selected = dict(items)
    for path in rows:
        assert selected["state/" + path] == 1
    assert m.MAX_PATHS == 512
    assert m.MAX_STATE == 6 * 1024**3
    assert m.MAX_FILE == 3 * 1024**3


@pytest.mark.parametrize("bad,why", (
    ("airdrop-radar/challenges/Contest/spec.json", "UNCLASSIFIED_STATE_FILE_STOP"),
    ("airdrop-radar/challenges/contest/unknown.json", "UNCLASSIFIED_STATE_FILE_STOP"),
    ("airdrop-radar/challenges/contest/artifacts/payload.bin", "CHALLENGE_ARTIFACT_INDEX_MISSING"),
    ("airdrop-radar/challenge-candidate-reviews/unknown.bin", "UNCLASSIFIED_STATE_FILE_STOP"),
    ("airdrop-radar/uv-cache/unknown.json", "UNCLASSIFIED_STATE_FILE_STOP"),
    ("public-proofs/private-seed.json", "UNCLASSIFIED_STATE_FILE_STOP"),
    ("public-proofs/proof-wrong-20261017T080200Z.json", "UNCLASSIFIED_STATE_FILE_STOP"),
))
def test_r945_unknown_radar_proofs_and_subtrees_never_auto_whitelisted(bad, why):
    m = module()
    c, s = fixtures(m)
    add(s, bad)
    with pytest.raises(m.Stop, match=why):
        m.plan(c, s)


def test_r945_known_radar_evidence_still_subject_to_size_limits():
    m = module()
    c, s = fixtures(m)
    add(s, "airdrop-radar/events.jsonl")
    s["files"][-1]["size"] = 3 * 1024**3 + 1
    with pytest.raises(m.Stop, match="STATE_FILE_TYPE_OR_SIZE"):
        m.plan(c, s)


def test_r948_indexed_challenge_artifact_bytes_retained_in_state_plan():
    m = module()
    c, s = fixtures(m)
    index = "airdrop-radar/challenges/contest_2026/artifacts.json"
    nested = "airdrop-radar/challenges/contest_2026/artifacts/rules/v1.pdf"
    add(s, index, nested)
    _, chosen = m.plan(c, s)
    assert dict(chosen)["state/" + nested] == 1
    assert m.MAX_ARTIFACT == 10 * 1024**2


@pytest.mark.parametrize("path,expected", (
    ("airdrop-radar/challenges/contest/artifacts/rules.pdf",
     "CHALLENGE_ARTIFACT_INDEX_MISSING"),
    ("airdrop-radar/challenges/contest/artifacts/../../seed.txt", "PATH_UNSAFE"),
    ("airdrop-radar/challenges/contest/artifacts/.ssh/key", "PATH_UNSAFE"),
    ("airdrop-radar/challenges/contest/artifacts/a/b/c/d/e", "PATH_UNSAFE"),
))
def test_r948_missing_artifact_index_and_unsafe_nested_names_stop(path, expected):
    m = module()
    c, s = fixtures(m)
    add(s, path)
    with pytest.raises(m.Stop, match=expected):
        m.plan(c, s)


def test_r948_original_ten_mib_artifact_limit_remains_fail_closed():
    m = module()
    c, s = fixtures(m)
    add(s, "airdrop-radar/challenges/c/artifacts.json",
        "airdrop-radar/challenges/c/artifacts/payload.pdf")
    s["files"][-1]["size"] = m.MAX_ARTIFACT + 1
    with pytest.raises(m.Stop, match="CHALLENGE_ARTIFACT_TOO_LARGE"):
        m.plan(c, s)


@pytest.mark.parametrize("name", (
    "monitor-config.json", "monitor-heartbeat.json", "alert-outbox.json",
    "discord-notifier-state.json", "action-candidates.json",
    "action-inbox.json", "action-executions.json",
))
def test_r956_exact_original_operational_state_retained(name):
    m = module()
    cap, inv = fixtures(m)
    path = "airdrop-radar/" + name
    add(inv, path)
    _, selected = m.plan(cap, inv)
    assert dict(selected)["state/" + path] == 1
    assert m.MAX_PATHS == 512 and m.MAX_STATE == 6 * 1024**3


@pytest.mark.parametrize("name", (
    "alert-outbox.lock", "action-inbox.lock", "action-executions.lock",
    "action-candidates.lock", "discord-notifier-state.json.tmp",
    "action-inbox.json.backup", "secret-cache.json",
))
def test_r956_transient_or_unknown_operational_names_still_stop(name):
    m = module()
    cap, inv = fixtures(m)
    add(inv, "airdrop-radar/" + name)
    with pytest.raises(m.Stop, match="UNCLASSIFIED_STATE_FILE_STOP"):
        m.plan(cap, inv)
