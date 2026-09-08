"""Seedless production entrypoint for Observer plus Resident candidate refresh."""
from __future__ import annotations

from . import (
    knowledge_guard,
    observer,
    observer_core_local_continuity,
    observer_events_startup_transport_fallback,
    observer_events_stream_recovery,
    observer_events_targeted_recovery,
    observer_health_recovery,
    observer_lobby_capture_health_proof,
    observer_lobby_capture_service,
    observer_lobby_fallback_health,
    observer_lobby_spool_recovery,
    observer_lobby_startup_spool_recovery,
    observer_request_deadline,
    observer_resident_isolation,
    observer_resilience,
    observer_startup_resilience,
    observer_state_writer_isolation,
)


def main() -> None:
    # Lobby capture has its own systemd lifecycle. Point every read-side recovery
    # helper in this Resident process at that standalone spool before workers or
    # overlays inspect capture state. The capture service itself remains running
    # across Resident restarts.
    observer_lobby_capture_service.install_reader()
    # Production installs the read-only hot-room resilience overlay before the
    # Observer creates workers. The isolated Signer service is not imported,
    # restarted, or invoked by this startup path.
    observer_resilience.install()
    # HTTP client read timeouts are inactivity timers, not total request timers.
    # Bound the whole live/export request so one trickling response cannot pin a
    # hot-room worker until retained history has already moved past its cursor.
    observer_request_deadline.install()
    # A persisted core cursor must catch up from retained evidence before the
    # first post-restart live tail is allowed to advance it.
    observer_startup_resilience.install()
    # A separate GET-only lobby capture service provides a bounded local shock
    # absorber. If a live tail later reveals a hole, use local captured rows before
    # the moving server retained ring.
    observer_lobby_spool_recovery.install()
    # The lobby spool is durable across Resident restarts. Drain its contiguous
    # persisted prefix before startup catch-up falls back to the moving server ring.
    observer_lobby_startup_spool_recovery.install()
    # PR #82 proved incremental streaming is required for real events gaps at
    # startup. Keep using that same GET-only path after startup for events live
    # errors and live-tail holes; lobby continues through its local spool overlay.
    observer_events_stream_recovery.install()
    # Never consume the whole events export when a live read has already proved an
    # exact small gap. Stop at that endpoint; steady live transport errors remain
    # fail-closed until a concrete missing interval exists.
    observer_events_targeted_recovery.install()
    # A single transient startup probe failure still retries the cheap events live
    # read. Repeated non-rate-limit transport failures escalate to the existing
    # incremental streaming startup path instead of pinning startup forever.
    observer_events_startup_transport_fallback.install()
    # If a failed lobby live read is fully covered by the already-installed local
    # spool/server fallback chain, clear only that stale live-error health record.
    observer_lobby_fallback_health.install()
    # A failed gap-recovery health record must not stay red forever after a later
    # successful contiguous/empty live cycle. Install after recovery overlays so a
    # fresh failure from the current cycle remains fail-closed and visible.
    observer_health_recovery.install()
    # Final core continuity semantics: while the independent lobby capture is still
    # behind a proven gap, keep the rich cursor fixed instead of prematurely
    # classifying server-ring loss; on restart, a fresh persisted local capture can
    # satisfy lobby continuity without a redundant server export. For an exact
    # events startup gap, consume only that retained interval and account a proven
    # absent suffix exactly once rather than retrying an impossible target forever.
    observer_core_local_continuity.install()
    # If the rich lobby GET fails but the independent capture lane has just
    # completed a successful poll at exactly the same cursor, that alternate lane
    # is sufficient read-side health evidence; do not leave core health red merely
    # because the redundant rich transport path timed out.
    observer_lobby_capture_health_proof.install()
    # Full multi-megabyte state serialization/fsync must not monopolize the same
    # asyncio loop that owns lobby/events reads. Generation tracking keeps newer
    # mutations dirty while disk I/O runs off-loop.
    observer_state_writer_isolation.install()
    # CPU-heavy Resident scoring/outbox maintenance remains in its own supervised
    # child process. Lobby capture is deliberately not a Resident child anymore.
    observer_resident_isolation.install()
    # Source-backed onboarding topics fail closed when their pinned registry is
    # stale or invalid. This changes eligibility only; installation performs no
    # Technocore write and grants no signing authority to Resident.
    knowledge_guard.install()
    # observe_forever owns the OS lock, async workers, read budget and signal handling.
    observer.observe_forever()


if __name__ == "__main__":
    main()
