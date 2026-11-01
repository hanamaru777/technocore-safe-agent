"""R1100: synthetic-only recipient-bound encrypted seed transport."""
import base64
import importlib.util
import json
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
FILE=ROOT/"packaging/migration/r1100_synthetic_recipient_rewrap.py"
spec=importlib.util.spec_from_file_location("r1100_fixture",FILE)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def test_random_synthetic_full_original_canonical_roundtrip():
    out=m.rehearsal()
    assert out["result"]=="SYNTHETIC_RECIPIENT_REWRAP_PASS"
    assert out["same_synthetic_did"] is True
    assert out["original_full_length_signing"] is True
    assert out["original_seed_used"] is False
    assert out["production_hosts_contacted"] is False
    assert out["live_seed_export"]=="NOT_IMPLEMENTED"
    assert out["cutover"]=="NO_GO"


def test_wrong_recipient_destination_approval_and_tamper_all_rejected():
    original=m._source()
    key=m.Ed25519PrivateKey.generate()
    seed=bytearray(key.private_bytes_raw())
    pub1=m.X25519PrivateKey.generate()
    pub2=m.X25519PrivateKey.generate()
    did=original.did_of(key)
    host1="a"*64;host2="b"*64;approval="c"*64
    try:
        blob=m._seal_fixture(seed,pub1.public_key().public_bytes_raw(),did,
                             host1,host2,approval)
        assert bytes(seed) not in blob
        opened=m._open_fixture(blob,pub1,did,host1,host2,approval)
        assert opened==seed
        opened[:]=b"\x00"*len(opened)
        with pytest.raises(m.Stop,match="TRANSFER_CONTEXT_STOP"):
            m._open_fixture(blob,pub2,did,host1,host2,approval)
        with pytest.raises(m.Stop,match="TRANSFER_CONTEXT_STOP"):
            m._open_fixture(blob,pub1,did,host1,"d"*64,approval)
        with pytest.raises(m.Stop,match="TRANSFER_CONTEXT_STOP"):
            m._open_fixture(blob,pub1,did,host1,host2,"d"*64)
        data=json.loads(blob)
        payload=bytearray(base64.b64decode(data["ciphertext"]))
        payload[-1]^=1
        data["ciphertext"]=base64.b64encode(payload).decode("ascii")
        with pytest.raises(m.Stop,match="TRANSFER_AUTH_STOP"):
            m._open_fixture(m._json(data),pub1,did,host1,host2,approval)
        dup=blob.replace(b'"context":',b'"context":{}, "context":',1)
        with pytest.raises(m.Stop,match="ENVELOPE_SCHEMA_STOP"):
            m._open_fixture(dup,pub1,did,host1,host2,approval)
    finally:
        seed[:]=b"\x00"*len(seed)


def test_no_real_access_and_no_generic_cli():
    text=FILE.read_text(encoding="utf8")
    assert "import oci" not in text
    assert "import boto3" not in text
    assert "import socket" not in text
    assert "subprocess" not in text
    assert "get_secret_bundle" not in text
    assert "SIGN_SEED" not in text
    assert "sys.argv" not in text
    assert m.PURPOSE=="SYNTHETIC_NO_LIVE_SEED"
