"""R1130 offline subprocess binary relay tests, no SSH/Oracle/AWS involved."""
import json
import sys
from pathlib import Path

import pytest

SRC=Path(__file__).resolve().parents[1]/"packaging/migration"
sys.path.insert(0,str(SRC))
import r1130_ephemeral_binary_relay as R

def children(tmp_path,*,good_magic=True,good_receipt=True,source_status=0):
    sender=tmp_path/"synthetic_source.py"
    receiver=tmp_path/"synthetic_receiver.py"
    payload=(b"FLOPST01" if good_magic else b"UNTRUST0")+b"A"*40960
    sender.write_text(
        "import sys\n"
        "sys.stdin.buffer.read()\n"
        "sys.stdout.buffer.write("+repr(payload)+")\n"
        "sys.stdout.buffer.flush()\n"
        "sys.exit("+str(source_status)+")\n",encoding="utf8")
    report={"phase":"R1129","result":"PROVISIONAL_CIPHERTEXT_STORED_ONLY",
            "files":3,"bytes":40968,"aead_verified":False,
            "source_complete":False,"sqlite_epoch":"NOT_PROVEN",
            "history_finality":"UNKNOWN","signer_portability":"NOT_PROVEN",
            "activated":False,"cutover":"NO_GO",
            "oci_retirement":"STRICT_NO_GO"}
    if not good_receipt:report["cutover"]="GO"
    receiver.write_text(
        "import sys\n"
        "data=sys.stdin.buffer.read()\n"
        "sys.stdout.buffer.write("+repr(json.dumps(report).encode())+")\n",
        encoding="utf8")
    return ([sys.executable,"-I","-B",str(sender)],
            [sys.executable,"-I","-B",str(receiver)])

def test_binary_forward_success_never_authorizes_cutover(tmp_path):
    a,b=children(tmp_path)
    material=bytearray(b"synthetic-private-source-control")
    r=R.relay(a,b,material,timeout=25)
    assert r["result"]=="CIPHERTEXT_RELAY_ONLY"
    assert r["ciphertext_bytes"]==40968
    assert r["activated"] is False and r["cutover"]=="NO_GO"
    assert set(material)=={0}

def test_forged_positive_receipt_rejected_and_zeroed(tmp_path):
    a,b=children(tmp_path,good_receipt=False)
    material=bytearray(b"synthetic-control")
    with pytest.raises(R.Stop,match="REPORT_RELEASE_STOP"):
        R.relay(a,b,material,timeout=25)
    assert set(material)=={0}

def test_wrong_magic_never_forwards_success(tmp_path):
    a,b=children(tmp_path,good_magic=False)
    material=bytearray(b"synthetic-control")
    with pytest.raises(R.Stop,match="SOURCE_MAGIC_STOP"):
        R.relay(a,b,material,timeout=25)
    assert set(material)=={0}

def test_source_failure_never_reports_success(tmp_path):
    a,b=children(tmp_path,source_status=42)
    material=bytearray(b"synthetic-control")
    with pytest.raises(R.Stop,match="CHILD_EXIT_STOP"):
        R.relay(a,b,material,timeout=25)
    assert set(material)=={0}

def test_oversize_refused_and_invalid_executable_stop(tmp_path,monkeypatch):
    a,b=children(tmp_path)
    monkeypatch.setattr(R,"MAX_BYTES",1024)
    material=bytearray(b"synthetic-control")
    with pytest.raises(R.Stop,match="WIRE_BOUND_STOP"):
        R.relay(a,b,material,timeout=25)
    assert set(material)=={0}
    with pytest.raises(R.Stop,match="SSH_BINARY_STOP"):
        R.safe_argv(["./ssh","one"])

def test_fixed_json_receipt_schema_and_duplicate_key_rejection():
    good={"phase":"R1129","result":"PROVISIONAL_CIPHERTEXT_STORED_ONLY",
          "files":3,"bytes":20,"aead_verified":False,"source_complete":False,
          "sqlite_epoch":"NOT_PROVEN","history_finality":"UNKNOWN",
          "signer_portability":"NOT_PROVEN","activated":False,
          "cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}
    assert R.strict_receipt(json.dumps(good).encode())["cutover"]=="NO_GO"
    with pytest.raises(R.Stop,match="DUPLICATE_REPORT_KEY"):
        R.strict_receipt(b'{"phase":"R1129","phase":"R1129"}')
    good["aead_verified"]=True
    with pytest.raises(R.Stop,match="REPORT_RELEASE_STOP"):
        R.strict_receipt(json.dumps(good).encode())


def test_prelaunch_pin_rejection_zeroizes_owner_input():
    material=bytearray(b"synthetic-owner-packet-never-log")
    with pytest.raises(R.Stop,match="SSH_BINARY_STOP"):
        R.relay(["./bad-ssh","source"],["./bad-ssh","target"],
                material,timeout=25)
    assert set(material)=={0}


def test_receiver_cannot_report_more_ciphertext_than_relay_sent(tmp_path):
    src,dst=children(tmp_path)
    dest=tmp_path/"synthetic_receiver.py"
    source=dest.read_text(encoding="utf8")
    assert '"bytes": 40968' in source
    dest.write_text(source.replace('"bytes": 40968','"bytes": 40969'),
                    encoding="utf8")
    material=bytearray(b"synthetic-owner-control")
    with pytest.raises(R.Stop,match="RECEIPT_BYTES_STOP"):
        R.relay(src,dst,material,timeout=25)
    assert set(material)=={0}
