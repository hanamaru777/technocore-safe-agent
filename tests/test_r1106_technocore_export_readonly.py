"""R1106 gets no live network in CI; fixture carries synthetic public bytes."""
import hashlib
import importlib.util
import json
from pathlib import Path
import pytest
FILE=Path(__file__).resolve().parents[1]/"packaging/migration/r1106_technocore_export_readonly.py"
spec=importlib.util.spec_from_file_location("r1106",FILE)
r=importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

def export(seqs=(1,2,3)):
    return b"".join(json.dumps({"seq":n,"from":"fake-did","nonce":str(n),"text":"synthetic"}).encode()+b"\n" for n in seqs)

def test_default_no_network_and_strict_no_go():
    report=r.audit_public_room()
    assert report["operation"]=="OFFLINE"
    assert report["post_finality"]=="NOT_PROVEN"
    assert report["source_archive"]=="NOT_AUTHORIZED"
    assert report["oci_retirement"]=="STRICT_NO_GO"

def test_contiguous_retained_ring_still_cannot_certify_full_history():
    data=export((41,42,43))
    report=r.audit_public_room("close1",fetcher=lambda room:(data,"7"))
    assert report["public_room_export"]=="RETAINED_RING_ONLY"
    assert report["export_count"]==3
    assert report["export_sha256"]==hashlib.sha256(data).hexdigest()
    assert report["post_finality"]=="NOT_PROVEN"
    assert "fake-did" not in str(report)
    assert "close1" not in str(report)

@pytest.mark.parametrize("case",[
  "gap","duplicate","reverse","negative","boolean","torn","oversized","bad_json",
  "duplicate_key","empty","bad_generation","unknown_generation","wrong_type",
  "private","path_traversal","no_reader","unicode_invalid"
])
def test_all_missing_or_incomplete_upstream_data_fails_closed(case):
    data=export()
    generation="7"
    room="close1"
    if case=="gap":data=export((1,3))
    if case=="duplicate":data=export((1,2,2))
    if case=="reverse":data=export((3,2,1))
    if case=="negative":data=export((-1,))
    if case=="boolean":data=b'{"seq":true}\n'
    if case=="torn":data=data.rstrip(b"\n")
    if case=="oversized":data=b"z"*(r.MAX_BYTES+1)
    if case=="bad_json":data=b"{oops}\n"
    if case=="duplicate_key":data=b'{"seq":1,"seq":2}\n'
    if case=="empty":data=b""
    if case=="bad_generation":generation="0"
    if case=="unknown_generation":generation="not-a-generation"
    if case=="wrong_type":data="not-bytes"
    if case=="private":room="p-secret"
    if case=="path_traversal":room="../rooms"
    if case=="no_reader":
        def fail(room):raise OSError("test")
        reader=fail
    else:reader=lambda room:(data,generation)
    if case=="unicode_invalid":reader=lambda room:(b'{"seq":1,"text":"\xff"}\n',"7")
    result=r.audit_public_room(room,fetcher=reader)
    if case=="empty":
        assert result["public_room_export"]=="EMPTY_UNVERIFIED"
    else:
        assert result["public_room_export"]=="REJECTED_OR_UNAVAILABLE"
    assert result["post_finality"]=="NOT_PROVEN"
    assert result["five_routes"]=="NOT_PROVEN"
    assert result["cutover"]=="NO_GO"
    assert result["oci_retirement"]=="STRICT_NO_GO"

def test_cli_offline_only_without_input(capsys):
    assert r.main([])==0
    report=json.loads(capsys.readouterr().out)
    assert report["operation"]=="OFFLINE"
    assert report["public_room_export"]=="NOT_VERIFIED"

def test_bad_cli_flags_rejected(capsys):
    assert r.main(["--post"])==2
    assert "INVALID_ARGUMENTS" in capsys.readouterr().out
