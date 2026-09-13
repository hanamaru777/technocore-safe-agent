"""Local-only Sonnet-2 planning CLI."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from . import sonnet_planner as planner
from . import sonnet_preflight as preflight

MAX_INPUT_BYTES = 64 * 1024

CONTEST_METADATA = {
    "contest_id": "sonnet-2",
    "rules_version": "0.5",
    "package_version": "0.5.0-draft",
    "rules_status": "draft",
    "opening": "2026-09-11T12:00:00Z",
    "deadline": "2026-09-18T12:00:00Z",
    "cmudict_sha256": preflight.CMUDICT_SHA256,
    "official_repository": "https://github.com/flop-labs/technocore-sonnet-challenge",
}


class ToolInputError(ValueError):
    pass


class _JsonArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ToolInputError("arguments_invalid")


def _read_small_text(path: str | Path, *, label: str) -> str:
    source = Path(path)
    try:
        size = source.stat().st_size
    except OSError as error:
        raise ToolInputError(f"{label}_unreadable") from error
    if size > MAX_INPUT_BYTES:
        raise ToolInputError(f"{label}_too_large")
    try:
        return source.read_text("utf-8")
    except (OSError, UnicodeError) as error:
        raise ToolInputError(f"{label}_unreadable") from error


def load_roster(path: str | Path) -> list[str]:
    text = _read_small_text(path, label="roster")
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise ToolInputError("roster_json_invalid") from error
    if isinstance(value, dict):
        value = value.get("roster")
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ToolInputError("roster_format_invalid")
    return list(value)


def load_poem(path: str | Path) -> list[list[str]]:
    text = _read_small_text(path, label="poem")
    source_lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(source_lines) != 14:
        raise ToolInputError(f"poem_line_count_invalid:{len(source_lines)}")
    lines = [line.split() for line in source_lines]
    if any(not line for line in lines):
        raise ToolInputError("poem_shape_invalid")
    return lines


def load_dictionary(path: str | Path) -> dict[str, int]:
    try:
        raw = preflight.verify_cmudict(path)
        return preflight.parse_cmudict(raw)
    except (OSError, UnicodeError, preflight.PreflightError) as error:
        raise ToolInputError(str(error)) from error


def _assignment_json(assignment: planner.AssignmentResult) -> list[list[dict[str, str]]]:
    return [
        [
            {"token": word.token, "contributor_did": word.contributor_did}
            for word in line
        ]
        for line in assignment.lines
    ]


def build_report(
    roster: list[str],
    lines: list[list[str]],
    dictionary: dict[str, int],
) -> dict:
    assignment, mechanical = planner.solve_and_validate(lines, roster, dictionary)
    literary = planner.literary_readiness(lines)
    publication = planner.publication_readiness(mechanical)
    return {
        "ok": True,
        "tool": "technocore-safe-agent/sonnet-tool",
        "metadata": dict(CONTEST_METADATA),
        "assignment": _assignment_json(assignment),
        "contributor_counts": assignment.contributor_counts,
        "balance_spread": assignment.balance_spread,
        "mechanical": {
            "status": "PASS",
            "line_syllables": list(mechanical.line_syllables),
            "canonical_text": mechanical.canonical_text,
            "poem_sha256": mechanical.poem_sha256,
            "byte_count": mechanical.byte_count,
            "x_chunks": list(mechanical.x_chunks),
        },
        "literary": asdict(literary),
        "publication": asdict(publication),
        "warning": (
            "Planning output only. Literary review, roster consent, accepted turns, "
            "X publication and referee receipts are not performed or proven by this tool."
        ),
    }


def _blocking_json(error: planner.PlanningError) -> list[dict]:
    return [asdict(item) for item in error.blocking]


def error_report(error: Exception) -> dict:
    payload = {
        "ok": False,
        "tool": "technocore-safe-agent/sonnet-tool",
        "metadata": dict(CONTEST_METADATA),
        "error": str(error) or error.__class__.__name__,
    }
    if isinstance(error, planner.PlanningError) and error.blocking:
        payload["blocking"] = _blocking_json(error)
    return payload


def run(roster_path: str, poem_path: str, dictionary_path: str) -> dict:
    roster = load_roster(roster_path)
    lines = load_poem(poem_path)
    dictionary = load_dictionary(dictionary_path)
    return build_report(roster, lines, dictionary)


def _parser() -> argparse.ArgumentParser:
    parser = _JsonArgumentParser(
        prog="python -m flop_agent.sonnet_tool",
        description="Local-only Sonnet-2 roster/poem planning utility",
    )
    parser.add_argument("--roster", required=True, help="JSON list or {'roster': [...]} file")
    parser.add_argument("--poem", required=True, help="14-line poem text file")
    parser.add_argument("--dictionary", required=True, help="official frozen cmudict.dict file")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        report = run(args.roster, args.poem, args.dictionary)
        code = 0
    except (ToolInputError, planner.PlanningError, preflight.PreflightError, ValueError) as error:
        report = error_report(error)
        code = 2
    json.dump(report, sys.stdout, ensure_ascii=False, sort_keys=True, indent=2)
    sys.stdout.write("\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
