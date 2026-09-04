"""Seedless production entrypoint for Observer plus Resident candidate refresh."""
from __future__ import annotations

from . import observer, observer_resilience


def main() -> None:
    # Production installs the read-only hot-room resilience overlay before the
    # Observer creates workers. Signer/write code is not imported or touched.
    observer_resilience.install()
    # observe_forever owns the OS lock, async workers, read budget and signal handling.
    # Its resident worker refreshes quality/relationship/candidates independently of reads.
    observer.observe_forever()


if __name__ == "__main__":
    main()
