"""R1087 two-pass full AEAD before a single plaintext byte is emitted."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import sqlite3
import sys
import pytest

F=Path(__file__).resolve().parents[1]/"packaging/migration/r1087_verified_plaintext_source.py"
spec=importlib.util.spec_from_file_location("r1087_tested",F)
m=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=m
spec.loader.exec_module(m)
POSIX=pytest.mark.skipif(os.name!="posix" or os.geteuid()==0,
                         reason="nonroot private POSIX offhost only")

@pytest.fixture
def sample(tmp_path):
    os.chmod(tmp_path,0o700)
    app=tmp_path/"app";state=tmp_path/"state"
    app.mkdir(mode=0o700);state.mkdir(mode=0o700)
    (app/"application.txt").write_bytes(bytes(range(128))*1900)
    (app/"internal").symlink_to("application.txt")
    for name in m.T.G.DATABASES:
        with sqlite3.connect(state/name) as c:
            c.execute("CREATE TABLE messages(seq INTEGER PRIMARY KEY)")
            c.execute("INSERT INTO messages VALUES (10)")
    recovery=os.urandom(48)
    archive=tmp_path/"sealed"
    m.T.seal(app,state,archive,recovery,source_head=m.T.HEAD)
    return archive,recovery

@POSIX
def test_two_pass_full_aead_and_no_source_disk_copy(sample):
    archive,recovery=sample
    stream=io.BytesIO()
    result=m.preverify_then_stream(archive,recovery,stream)
    assert result["operation"]=="OFFHOST_VERIFIED_PLAINTEXT_STREAM_ONLY"
    assert result["cutover"]=="NO_GO"
    assert stream.getvalue()==b"".join(m.T.decrypt(archive,recovery))
    assert result["plaintext_sha256"]==hashlib.sha256(stream.getvalue()).hexdigest()

@POSIX
@pytest.mark.parametrize("failure",["wrong_key","wrong_hash","missing_commit",
                                    "part_corrupt","writable_part","symlink_part"])
def test_invalid_archive_zero_plaintext_leak(sample,failure):
    archive,recovery=sample
    expected=None
    if failure=="wrong_key":recovery=os.urandom(48)
    if failure=="wrong_hash":expected="f"*64
    if failure=="missing_commit":(archive/"commit.bin").unlink()
    part=archive/"part-0000.bin"
    if failure=="part_corrupt":
        with part.open("r+b") as f:
            f.seek(70);b=f.read(1);f.seek(70);f.write(bytes([b[0]^1]))
    if failure=="writable_part":part.chmod(0o644)
    if failure=="symlink_part":
        part.rename(archive/"relocated")
        part.symlink_to("relocated")
    out=io.BytesIO()
    with pytest.raises((m.Stop,m.T.Stop,m.T.C.Stop,OSError,ValueError)):
        m.preverify_then_stream(archive,recovery,out,
                                expected_sha256=expected)
    assert out.getvalue()==b""

@POSIX
def test_output_error_does_not_issue_success_receipt(sample):
    archive,recovery=sample
    class Short(io.BytesIO):
        def write(self,b):
            if self.tell()>100: return 0
            return super().write(bytes(b)[:100])
    with pytest.raises(m.Stop,match="OUTPUT_ABORT_STOP"):
        m.preverify_then_stream(archive,recovery,Short())

def test_legal_scope_no_remote_or_wallet_operations():
    content=F.read_text()
    for item in ("subprocess.Popen","systemctl stop","oci.auth",
                 "OCI_VAULT_SECRET_OCID","terraform destroy",
                 "ssh-keyscan"):
        assert item not in content
