"""Seedless production entrypoint for Observer plus Resident candidate refresh."""
from __future__ import annotations

from . import observer


def main() -> None:
    # observe_forever owns the OS lock, async workers, read budget and signal handling.
    # Its resident worker refreshes quality/relationship/candidates independently of reads.
    observer.observe_forever()


if __name__ == "__main__":
    main()
