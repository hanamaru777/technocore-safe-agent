from flop_agent import core


def test_bundled_official_signer_hash_is_pinned():
    assert core.signer_sha256() == core.SIGNER_SHA256


def test_no_tracked_secret_material():
    assert core.secret_scan() == []
