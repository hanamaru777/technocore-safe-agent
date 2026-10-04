"""Small action-first formatter for unsolicited Discord notices.

This module is presentation-only. It never sends messages or performs external
work. Callers decide when a notice is warranted; this module only keeps the
human-facing default compact and structurally consistent.
"""
from __future__ import annotations

from dataclasses import dataclass

KINDS = {"ACTION", "WARNING", "DONE", "FAILED"}
EMOJI = {
    "ACTION": "🟠",
    "WARNING": "⚠️",
    "DONE": "✅",
    "FAILED": "⛔",
}
MAX_DEFAULT_LINES = 6
MAX_TITLE = 72
MAX_LINE = 420


class NoticeFormatError(ValueError):
    """Raised when a default notice would violate the compact UX contract."""


def _one_line(value: object, *, label: str, limit: int = MAX_LINE) -> str:
    if not isinstance(value, str):
        raise NoticeFormatError(f"discord_notice_{label}_invalid")
    text = " ".join(value.split()).strip()
    if not text or len(text) > limit:
        raise NoticeFormatError(f"discord_notice_{label}_invalid")
    return text


@dataclass(frozen=True)
class Notice:
    kind: str
    title: str
    impact: str
    state: str
    next_action: str
    deadline: str | None = None
    detail: str | None = None

    def render(self) -> str:
        if self.kind not in KINDS:
            raise NoticeFormatError("discord_notice_kind_invalid")
        title = _one_line(self.title, label="title", limit=MAX_TITLE)
        impact = _one_line(self.impact, label="impact")
        state = _one_line(self.state, label="state")
        next_action = _one_line(self.next_action, label="next_action")
        lines = [
            f"{EMOJI[self.kind]} {title}",
            f"影響: {impact}",
            f"状態: {state}",
            f"次: {next_action}",
        ]
        if self.deadline is not None:
            lines.append(f"期限: {_one_line(self.deadline, label='deadline')}")
        if self.detail is not None:
            lines.append(f"詳細: {_one_line(self.detail, label='detail')}")
        if len(lines) > MAX_DEFAULT_LINES:
            raise NoticeFormatError("discord_notice_too_many_lines")
        if sum(line.startswith("次:") for line in lines) != 1:
            raise NoticeFormatError("discord_notice_next_action_invalid")
        return "\n".join(lines)


def render(
    kind: str,
    title: str,
    *,
    impact: str,
    state: str,
    next_action: str,
    deadline: str | None = None,
    detail: str | None = None,
) -> str:
    return Notice(
        kind=kind,
        title=title,
        impact=impact,
        state=state,
        next_action=next_action,
        deadline=deadline,
        detail=detail,
    ).render()
