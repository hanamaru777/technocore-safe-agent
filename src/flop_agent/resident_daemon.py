"""Seedless production entrypoint for Observer plus Resident candidate refresh."""
from __future__ import annotations

from . import knowledge_guard, observer, observer_resilience


def main() -> None:
    # Production installs the read-only hot-room resilience overlay before the
    # Observer creates workers. The isolated Signer service is not imported,
    # restarted, or invoked by this startup path.
    observer_resilience.install()
    # Source-backed onboarding topics fail closed when their pinned registry is
    # stale or invalid. This changes eligibility only; installation performs no
    # Technocore write and grants no signing authority to Resident.
    knowledge_guard.install()
    # observe_forever owns the OS lock, async workers, read budget and signal handling.
    # Its resident worker refreshes quality/relationship/candidates independently of reads.
    observer.observe_forever()


if __name__ == "__main__":
    main()
