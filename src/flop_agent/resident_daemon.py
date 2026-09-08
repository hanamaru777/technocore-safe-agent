"""Seedless production entrypoint for Observer plus Resident candidate refresh."""
from __future__ import annotations

from . import (
    knowledge_guard,
    observer,
    observer_lobby_spool_recovery,
    observer_request_deadline,
    observer_resident_isolation,
    observer_resilience,
    observer_startup_resilience,
    observer_state_writer_isolation,
)


def main() -> None:
    # Production installs the read-only hot-room resilience overlay before the
    # Observer creates workers. The isolated Signer service is not imported,
    # restarted, or invoked by this startup path.
    observer_resilience.install()
    # HTTP client read timeouts are inactivity timers, not total request timers.
    # Bound the whole live/export request so one trickling response cannot pin a
    # hot-room worker until retained history has already moved past its cursor.
    observer_request_deadline.install()
    # A persisted core cursor must catch up from the retained ring before the
    # first post-restart live tail is allowed to advance it.
    observer_startup_resilience.install()
    # A separate GET-only lobby capture process provides a bounded local shock
    # absorber. If a live tail later reveals a hole, use local captured rows before
    # the moving server retained ring.
    observer_lobby_spool_recovery.install()
    # Full multi-megabyte state serialization/fsync must not monopolize the same
    # asyncio loop that owns lobby/events reads. Generation tracking keeps newer
    # mutations dirty while disk I/O runs off-loop.
    observer_state_writer_isolation.install()
    # CPU-heavy Resident scoring/outbox maintenance and the lobby capture lane run
    # in supervised child processes, separate from the Observer process GIL.
    observer_resident_isolation.install()
    # Source-backed onboarding topics fail closed when their pinned registry is
    # stale or invalid. This changes eligibility only; installation performs no
    # Technocore write and grants no signing authority to Resident.
    knowledge_guard.install()
    # observe_forever owns the OS lock, async workers, read budget and signal handling.
    observer.observe_forever()


if __name__ == "__main__":
    main()
