"""R1099 synthetic AES-GCM signer/nonce/DID compatibility: no real key."""
from pathlib import Path
import base64
import importlib.util
import json
import pytest

ROOT=Path(__file__).resolve().parents[1]
FILE=ROOT/"packaging/migration/r1099_k137_synthetic_signer_envelope.py"
sp=importlib.util.spec_from_file_location("r1099_fixture",FILE)
m=importlib.util.module_from_spec(sp)
sp.loader.exec_module(m)


def context():
    key=m.Ed25519PrivateKey.generate()
    source=m._source()
    did=source.did_of(key)
    host="a"*64
    seed=bytearray(key.private_bytes_raw())
    return seed,did,host


def test_offline_rehearsal_full_original_8k_and_unicode():
    result=m.rehearsal()
    assert result["result"]=="SYNTHETIC_ROUNDTRIP_ONLY"
    assert result["source_pin"]=="MATCH"
    assert result["same_synthetic_did"] is True
    assert result["max_say_utf8_bytes"]==16388
    assert result["max_note_utf8_bytes"]==8198
    assert result["network_calls"]==0
    assert result["original_seed_access"]=="NONE"
    assert result["k137_service"]=="NOT_DEPLOYED"
    assert result["cutover"]=="NO_GO"


def test_tamper_wrong_host_did_password_all_fail_closed():
    seed,did,host=context()
    password=b"offline-only-fake-password-for-synthetic-test"
    try:
        blob=m._seal_fixture(seed,password,did,host)
        assert b"seed" not in blob
        assert bytes(seed) not in blob
        result=m._unseal_fixture(blob,password,did,host)
        assert result==seed
        result[:]=b"\0"*len(result)
        with pytest.raises(m.Stop,match="ENVELOPE_BINDING_STOP"):
            m._unseal_fixture(blob,password,did,"b"*64)
        otherdid=m._source().did_of(m.Ed25519PrivateKey.generate())
        with pytest.raises(m.Stop,match="ENVELOPE_BINDING_STOP"):
            m._unseal_fixture(blob,password,otherdid,host)
        with pytest.raises(m.Stop,match="ENVELOPE_AUTH_STOP"):
            m._unseal_fixture(blob,b"wrong-synthetic-password-fails-closed",did,host)
        data=json.loads(blob)
        raw=bytearray(base64.b64decode(data["ciphertext"]))
        raw[0]^=1
        data["ciphertext"]=base64.b64encode(raw).decode()
        with pytest.raises(m.Stop,match="ENVELOPE_AUTH_STOP"):
            m._unseal_fixture(m._json(data),password,did,host)
        data=json.loads(blob)
        duplicate=blob.replace(b'"context":',b'"context":{}, "context":',1)
        with pytest.raises(m.Stop,match="ENVELOPE_SCHEMA_STOP"):
            m._unseal_fixture(duplicate,password,did,host)
    finally:
        seed[:]=b"\0"*len(seed)


def test_no_live_api_or_cli_secret_import():
    text=FILE.read_text(encoding="utf-8")
    assert "InstancePrincipalsSecurityTokenSigner" not in text
    assert "get_secret_bundle" not in text
    assert "boto3" not in text
    assert "subprocess" not in text
    assert "import socket" not in text
    assert "os.environ" not in text
    assert "sys.argv" not in text
    assert "load_key(" not in text
    assert m.PURPOSE=="SYNTHETIC_ONLY_NO_PRODUCTION_SIGNING"
    assert m.KDF_N==(1<<15)
