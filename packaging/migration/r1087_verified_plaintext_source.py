"""R1087 two-pass authenticated offhost source for disarmed streaming.

This deliberately has NO real SSH, Windows NTFS, Oracle, service control, or
operator permission. The only emitted data is R1001-verified plaintext over an
already owner-authenticated external pipe; the caller must establish transport.
The archived source remains on an independent non-root POSIX offhost machine.
A full pass validates the entire archive BEFORE ANY plaintext can be emitted.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys

def _load():
    p=Path(__file__).with_name("r1066_transfer.py")
    spec=importlib.util.spec_from_file_location("r1087_existing_transfer",p)
    m=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=m
    spec.loader.exec_module(m)
    return m

T=_load()
class Stop(ValueError):
    pass

def need(ok,why):
    if not ok: raise Stop(why)

def _file_census(archive):
    """Bind path/owner/inode/mtime to the two sequential AEAD passes."""
    root=T.private_dir(archive)
    need(os.name=="posix" and os.geteuid()!=0,"NONROOT_OFFHOST_ONLY")
    need(not any(root==Path(p) or Path(p) in root.parents
                 for p in T.BLOCKED_ROOTS),"PRODUCTION_ROOT_STOP")
    result={}
    for p in root.iterdir():
        st=p.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid()
             and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,
             "CIPHERTEXT_CUSTODY_STOP")
        result[p.name]=(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,
                        st.st_ctime_ns,st.st_mode)
    need(3<=len(result)<=T.C.MAX_PARTS+2,"PART_COUNT_STOP")
    return result

def _check_census(archive,pin):
    need(_file_census(archive)==pin,"OFFHOST_ARCHIVE_DRIFT_STOP")

def preverify_then_stream(archive,recovery,output,*,expected_sha256=None):
    """Verify the whole encrypted original before exposing ANY plaintext.

    Output has no commit marker: only a receiver independently authenticating
    the PINNED SSH transport, exact target identity and restored files may
    claim completion. Returning to caller is not a production migration GO.
    """
    need(type(recovery) is bytes and len(recovery)>=32,"RECOVERY_STOP")
    need(output is not None and callable(getattr(output,"write",None)) and
         not (hasattr(output,"isatty") and output.isatty()),"BINARY_OUTPUT_STOP")
    if expected_sha256 is not None:
        need(type(expected_sha256) is str and
             T.G.HEX.fullmatch(expected_sha256) is not None,
             "EXPECTED_PLAINTEXT_SHA_STOP")
    archive=Path(archive)
    before=_file_census(archive)
    sha=hashlib.sha256();total=0
    # R1001 checks AES-GCM FINAL, every part SHA256 and entire plaintext SHA.
    for block in T.decrypt(archive,recovery):
        total+=len(block)
        need(total<=T.C.MAX_SOURCE_BYTES,"SOURCE_BYTES_STOP")
        sha.update(block)
    _check_census(archive,before)
    validated_sha=sha.hexdigest()
    need(expected_sha256 is None or validated_sha==expected_sha256,
         "EXPECTED_PLAINTEXT_HASH_MISMATCH")
    # No live JSON or secrets are printed; second pass starts ONLY after full
    # independent ciphertext validation. The receiving K137 writer remains
    # DISARMED and cannot become an active signer here.
    replay=hashlib.sha256();sent=0
    try:
        for block in T.decrypt(archive,recovery):
            view=memoryview(block)
            at=0
            while at<len(view):
                written=output.write(view[at:])
                need(type(written) is int and written>0 and
                     written<=len(view)-at,"OUTPUT_ABORT_STOP")
                at+=written
            replay.update(block);sent+=len(block)
        need(sent==total and replay.digest()==sha.digest(),
             "TWO_PASS_DIGEST_STOP")
        _check_census(archive,before)
    finally:
        # Do not flush an unverified output or create any valid receipt here.
        # If a pipe failed, a receiver MUST reject the unfinished manifest.
        pass
    return {"operation":"OFFHOST_VERIFIED_PLAINTEXT_STREAM_ONLY",
            "plaintext_bytes":total,"plaintext_sha256":validated_sha,
            "source_epoch":"PROVISIONAL_UNFENCED",
            "ssh_origin":"EXTERNAL_NOT_PROVEN",
            "k137_disarmed_restore":"NOT_PROVEN",
            "cutover":"NO_GO","oci_retirement":"STRICT_NO_GO"}
