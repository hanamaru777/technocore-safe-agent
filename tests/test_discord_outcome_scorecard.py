import ast
import json
import inspect

from flop_agent import discord_outcome_scorecard as score


BASE_ACTIVITY = {
    "snapshot": {
        "problems": [],
        "critical": 0,
        "health": "ok",
        "last_refresh_age": "10秒前",
        "auto": {"enabled": True, "paused": False, "queued": 0},
    },
    "posts": 1,
    "eligible": 0,
    "ignored": 3,
    "blocked": 0,
    "reasons": {"初回DIDのためreview-only": 3},
    "zero_reason": None,
    "received": [
        {"conversation_id": "c1", "fingerprint": "abcdef123", "direction": "受信"},
        {"conversation_id": "c2", "fingerprint": "fedcba987", "direction": "受信"},
    ],
    "sent": [
        {"conversation_id": "c1", "fingerprint": "abcdef123", "direction": "送信"},
    ],
    "counterparts": 2,
    "interactions": [],
    "latest_post": None,
    "trusted": [{"fingerprint": "abcdef123"}],
    "trust_candidates": [],
    "bootstrap_pending": [],
}


def test_collaboration_counts_are_read_only_and_include_pruned_completed(monkeypatch):
    monkeypatch.setattr(
        score.collaboration,
        "load_state",
        lambda: {
            "records": {
                "a": {"stage": "task_candidate"},
                "b": {"stage": "human_review"},
                "c": {"stage": "completed"},
                "d": {"stage": "contacted"},
            },
            "completed_evidence_index": [{"id": "old-completed"}],
        },
    )
    assert score._collaboration_counts() == (2, 2)


def test_public_artifact_count_requires_published_repo_files(monkeypatch, tmp_path):
    docs = tmp_path / "docs"
    source = tmp_path / "src" / "flop_agent"
    docs.mkdir()
    source.mkdir(parents=True)
    (docs / "SONNET2_PLANNER.md").write_text("public docs", encoding="utf-8")
    (source / "sonnet_tool.py").write_text("# local-only tool\n", encoding="utf-8")
    profile = tmp_path / "public-profile.json"
    profile.write_text(
        json.dumps({
            "knowledge": {
                "public_artifacts": [
                    {
                        "id": "sonnet2-planner",
                        "kind": "public_utility",
                        "status": "published",
                        "documentation": "docs/SONNET2_PLANNER.md",
                        "entrypoint": "src/flop_agent/sonnet_tool.py",
                    },
                    {
                        "id": "missing",
                        "kind": "public_utility",
                        "status": "published",
                        "documentation": "docs/missing.md",
                        "entrypoint": "src/flop_agent/sonnet_tool.py",
                    },
                    {
                        "id": "unsafe-path",
                        "kind": "public_utility",
                        "status": "published",
                        "documentation": "../outside.md",
                        "entrypoint": "src/flop_agent/sonnet_tool.py",
                    },
                    {
                        "id": "draft",
                        "kind": "public_utility",
                        "status": "draft",
                        "documentation": "docs/SONNET2_PLANNER.md",
                        "entrypoint": "src/flop_agent/sonnet_tool.py",
                    },
                ]
            }
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(score, "_REPO_ROOT", tmp_path)
    monkeypatch.setattr(score, "_PUBLIC_PROFILE_PATH", profile)
    assert score._public_artifact_count() == 1


def test_public_artifact_count_fails_closed_on_bad_metadata(monkeypatch, tmp_path):
    profile = tmp_path / "public-profile.json"
    profile.write_text("not-json", encoding="utf-8")
    monkeypatch.setattr(score, "_REPO_ROOT", tmp_path)
    monkeypatch.setattr(score, "_PUBLIC_PROFILE_PATH", profile)
    assert score._public_artifact_count() == 0


def test_oldest_unresolved_direct_ignores_recorded_reply(monkeypatch):
    state = {
        "candidates": {
            "older": {
                "candidate_id": "c1",
                "status": "pending",
                "category": "conversation",
                "signals": {"direct_public_signed": True},
                "fingerprint": "abcdef123",
                "room": "lobby",
                "seq": 10,
                "created_at": "2026-09-13T00:00:00+00:00",
                "expires_at": "2099-01-01T00:00:00+00:00",
            },
            "newer": {
                "candidate_id": "c2",
                "status": "approved",
                "category": "conversation",
                "signals": {"direct_public_signed": True},
                "fingerprint": "fedcba987",
                "room": "work",
                "seq": 11,
                "created_at": "2026-09-13T00:05:00+00:00",
                "expires_at": "2099-01-01T00:00:00+00:00",
            },
        }
    }
    monkeypatch.setattr(score.resident, "load_state", lambda: state)
    unresolved = score._unresolved_direct({"sent": [{"conversation_id": "c1"}]})
    assert unresolved["candidate_id"] == "c2"
    assert unresolved["room"] == "work"
    assert unresolved["seq"] == 11


def test_activity_snapshot_adds_outcomes_without_reinterpreting_base(monkeypatch):
    original = dict(BASE_ACTIVITY)
    monkeypatch.setattr(score, "_ORIGINAL_ACTIVITY", lambda **_kwargs: original)
    monkeypatch.setattr(score, "_collaboration_counts", lambda: (2, 4))
    monkeypatch.setattr(score, "_public_artifact_count", lambda: 1)
    monkeypatch.setattr(score, "_unresolved_direct", lambda _activity: {"candidate_id": "c2"})
    result = score._activity_snapshot()
    assert result is not original
    assert result["signed_direct_requests"] == 2
    assert result["acked_replies"] == 1
    assert result["active_trusted"] == 1
    assert result["collaboration_active"] == 2
    assert result["collaboration_completed"] == 4
    assert result["public_artifacts"] == 1
    assert result["oldest_unresolved_direct"] == {"candidate_id": "c2"}


def test_status_prioritizes_outcomes_not_six_post_target(monkeypatch):
    activity = {
        **BASE_ACTIVITY,
        "signed_direct_requests": 2,
        "acked_replies": 1,
        "active_trusted": 1,
        "collaboration_active": 2,
        "collaboration_completed": 3,
        "public_artifacts": 1,
        "oldest_unresolved_direct": None,
    }
    monkeypatch.setattr(score, "_activity_snapshot", lambda **_kwargs: activity)
    rendered = score._status_message()
    assert "関係24h: 署名direct 2 / ACK返信 1 / ユニーク相手 2人" in rendered
    assert "継続成果: active trust 1 / 協業進行 2 / 協業完了 3 / 公開artifact 1" in rendered
    assert "safety cap 6、目標ではありません" in rendered
    assert "1/6" not in rendered
    assert "投稿しなかった主因: 投稿あり" not in rendered


def test_activity_message_surfaces_public_artifact(monkeypatch):
    activity = {
        **BASE_ACTIVITY,
        "signed_direct_requests": 2,
        "acked_replies": 1,
        "active_trusted": 1,
        "collaboration_active": 0,
        "collaboration_completed": 0,
        "public_artifacts": 1,
        "oldest_unresolved_direct": None,
    }
    monkeypatch.setattr(score, "_activity_snapshot", lambda **_kwargs: activity)
    rendered = score._activity_message()
    assert "公開artifact: 1" in rendered


def test_digest_keeps_gap_visibility_but_reports_non_action_reason(monkeypatch):
    activity = {
        **BASE_ACTIVITY,
        "signed_direct_requests": 2,
        "acked_replies": 1,
        "active_trusted": 1,
        "collaboration_active": 1,
        "collaboration_completed": 2,
        "public_artifacts": 1,
        "oldest_unresolved_direct": None,
    }
    monkeypatch.setattr(score, "_activity_snapshot", lambda **_kwargs: activity)
    monkeypatch.setattr(score.base, "_observer_metrics", lambda: {
        "unique_dids_discovered": 20,
        "returning_did_encounters": 3,
        "message_gaps": 12,
    })
    monkeypatch.setattr(score.base, "load_ui_state", lambda: {
        "digest_baseline": {
            "unique_dids_discovered": 10,
            "returning_did_encounters": 1,
            "message_gaps": 10,
        },
        "pending_gap_delta": 5,
    })
    saved = {}
    monkeypatch.setattr(score.base, "save_ui_state", lambda state: saved.update(state))
    rendered = score._digest(None)
    assert "6時間アウトカム" in rendered
    assert "新しいgap +2" in rendered
    assert "主な非アクション理由: 初回DIDのためreview-only" in rendered
    assert "協業完了 2 / 公開artifact 1" in rendered
    assert saved["pending_gap_delta"] == 0
    assert saved["digest_baseline"]["message_gaps"] == 12
    assert "投稿あり" not in rendered


def test_scorecard_has_no_network_signing_or_protocol_write_surface():
    source = inspect.getsource(score)
    tree = ast.parse(source)
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])
    assert imported_roots.isdisjoint({"httpx", "requests", "urllib", "socket", "subprocess"})
    forbidden_write_symbols = (
        "post_signed",
        "invoke_signer",
        "SIGN_SEED",
        "with_vault_seed",
    )
    assert all(token not in source for token in forbidden_write_symbols)
