import pytest

from flop_agent import tclk_note_review


NOW = 2_000_000_000_000


def _offer() -> dict:
    return {
        "id": "0x" + ("8" * 64),
        "frame_type": "offer",
        "read_only": True,
        "accepted": False,
        "rail": "paper",
        "job_proto": "a2a",
        "job_id": "boundary-open",
        "expires_ms": NOW + 900_000,
        "frame_sha256": "b" * 64,
    }


@pytest.mark.parametrize(
    "spec",
    [
        "use /kv/tclk-mat-en/mat-one?raw=1",
        "use https://technocore.chat/kv/tclk-mat-en/mat-one",
        "use /kv/tclk-mat-en/mat-one/child",
    ],
)
def test_material_dependency_must_be_a_standalone_exact_note_path(spec):
    calls = []

    def reader(namespace: str, key: str) -> str:
        calls.append((namespace, key))
        return spec

    with pytest.raises(tclk_note_review.ResolutionError, match="material_reference_not_exact"):
        tclk_note_review.resolve_offer(_offer(), reader=reader, now_ms=NOW)

    assert calls == [("tclk-job-en", "boundary-open")]
