"""Production-only presentation/routing overlay for new official challenge repos.

The existing Radar remains authoritative for extraction and before->after
comparison.  This module adds one deterministic HIGH evidence event when a new
non-archived `*challenge*` repository first appears in the official flop-labs
GitHub activity fact, then routes that event immediately through the existing
monitor/notifier path.  It never signs, registers, claims, spends, submits, or
posts protocol actions.
"""
from __future__ import annotations

import json
import re
import sys
from copy import deepcopy

from . import airdrop_monitor as monitor
from . import airdrop_radar as radar

SPECIAL_TYPE = "OFFICIAL_CHALLENGE_REPO_DISCOVERED"
SPECIAL_KEY_PREFIX = "challenge_repo:"
CHALLENGE_RE = re.compile(r"challenge", re.IGNORECASE)
_INSTALLED = False
_ORIGINAL_COMPARE = radar.compare_snapshots
_ORIGINAL_ROUTE = monitor._route
_ORIGINAL_SAFE_NEXT_STEP = monitor.safe_next_step


def _rows(value: object) -> dict[str, dict]:
    if isinstance(value, dict) and "value" in value:
        if value.get("source") != "github_org":
            return {}
        value = value.get("value")
    if not isinstance(value, list):
        return {}
    result: dict[str, dict] = {}
    for item in value:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name or len(name) > 100 or not CHALLENGE_RE.search(name):
            continue
        result[name] = {
            "repo_name": name,
            "default_branch": item.get("default_branch") if isinstance(item.get("default_branch"), str) else None,
            "pushed_at": item.get("pushed_at") if isinstance(item.get("pushed_at"), str) else None,
            "archived": bool(item.get("archived")),
            "source": "github_org",
        }
    return result


def _new_challenge_rows(before: object, after: object) -> list[dict]:
    old = _rows(before)
    new = _rows(after)
    return [
        deepcopy(new[name])
        for name in sorted(set(new) - set(old))
        if new[name]["archived"] is False
    ]


def _new_challenge_rows_from_event(event: object) -> list[dict]:
    if not isinstance(event, dict) or event.get("key") != "github_critical_repo_activity":
        return []
    return _new_challenge_rows(event.get("before"), event.get("after"))


def compare_snapshots(previous: dict | None, current: dict, *, now=None) -> dict:
    result = _ORIGINAL_COMPARE(previous, current, now=now)
    if result.get("baseline") is True or previous is None:
        return result

    before = previous.get("resolved_facts", {}).get("github_critical_repo_activity")
    after = current.get("resolved_facts", {}).get("github_critical_repo_activity")
    additions = _new_challenge_rows(before, after)
    if not additions:
        return result

    events = list(result.get("events", []))
    for row in additions:
        repo = row["repo_name"]
        events.append(
            radar._event(
                event_type=SPECIAL_TYPE,
                key=f"{SPECIAL_KEY_PREFIX}{repo}",
                before=None,
                after=row,
                severity="HIGH",
            )
        )
    result = dict(result)
    result["events"] = events
    return result


def route(event: dict) -> str:
    if event.get("type") == SPECIAL_TYPE and str(event.get("key", "")).startswith(SPECIAL_KEY_PREFIX):
        return "immediate"
    # The generic GitHub-activity change remains in the Evidence Ledger, but
    # avoid a second delayed digest for the exact cycle already escalated by
    # the dedicated challenge discovery event.
    if _new_challenge_rows_from_event(event):
        return "ledger_only"
    return _ORIGINAL_ROUTE(event)


def safe_next_step(event: dict) -> str:
    if event.get("type") == SPECIAL_TYPE:
        after = event.get("after") if isinstance(event.get("after"), dict) else {}
        repo = after.get("repo_name")
        if isinstance(repo, str) and repo:
            return (
                f"公式 flop-labs/{repo} のルールを固定し、challenge specとpre-contest readinessを今すぐ開始する。"
                "登録・署名・送信などのbinding actionは別承認まで実行しない。"
            )
        return (
            "新しい公式challenge repoのルールを固定し、challenge specとpre-contest readinessを開始する。"
            "binding actionは別承認まで実行しない。"
        )
    return _ORIGINAL_SAFE_NEXT_STEP(event)


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    radar.compare_snapshots = compare_snapshots
    monitor._route = route
    monitor.safe_next_step = safe_next_step
    _INSTALLED = True


def main() -> None:
    install()
    try:
        output = monitor.run_once()
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
