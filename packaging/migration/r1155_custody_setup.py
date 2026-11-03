"""Owner provisioning primitives, never invoked by ordinary/default CLI.

Recipient private key is generated/encrypted ONLY on the enrolled K137 isolated
signer. Source receives its public key, never its password/private key.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
import time
import warnings

sp=importlib.util.spec_from_file_location("r1155_setup_signer",Path(__file__).with_name("r1155_signer.py"))
S=importlib.util.module_from_spec(sp);sys.modules[sp.name]=S;sp.loader.exec_module(S)
H=S.H;C=S.C;K=S.K


def recipient_init(authority,password,store=S.STORE):
    import pwd
    H.need(sys.platform=="linux" and os.geteuid()==pwd.getpwnam("technocore-signer").pw_uid and
        hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()==authority.trust.context["destination"],"RECIPIENT_LOCAL_SIGNER_REQUIRED")
    H.need(type(password) is bytearray and 32<=len(password)<=1024,"RECIPIENT_PASSWORD_STOP")
    from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,BestAvailableEncryption
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    try:
        H.private_dir(store);path=store/"recipient.pem.enc"
        H.need(not path.exists() and not path.is_symlink(),"RECIPIENT_ALREADY_EXISTS")
        key=X25519PrivateKey.generate()
        H.exclusive(path,key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,BestAvailableEncryption(bytes(password))))
        return dict(recipient_public=key.public_key().public_bytes_raw().hex(),plaintext_persisted=False)
    finally:password[:]=b"\0"*len(password)


def install_source_public(request,expected_enrollment_sha):
    """Fix R1154's root:root 0640 readability without observer group access.

    Root installs PUBLIC request/config/code only. No seed fetch or service
    start. The existing explicitly invoked R1154 custody one-shot does that.
    """
    import pwd
    H.need(sys.platform=="linux" and os.geteuid()==0,"SOURCE_PUBLIC_ROOT_REQUIRED")
    H.shape(request,"enrollment enrollment_sha binding owner witness")
    H.need(request["enrollment_sha"]==expected_enrollment_sha,"SOURCE_PUBLIC_AUTHORITY_STOP")
    a=H.Authority(request["enrollment"],expected_enrollment_sha)
    K.approved(a,request["binding"],request["owner"],request["witness"],now=int(time.time()))
    got=H.Linux().reader.identity()
    H.need(got["host_digest"]==a.trust.context["host"] and got["source_head"]==C.G.SOURCE_HEAD,"SOURCE_PUBLIC_HOST_STOP")
    account=pwd.getpwnam("technocore-signer")
    H.need(account.pw_uid>1000,"SOURCE_PUBLIC_SIGNER_STOP")
    import grp
    dedicated=grp.getgrnam("technocore-signer").gr_gid
    H.need(account.pw_gid==dedicated and grp.getgrnam("technocore").gr_gid not in
        os.getgrouplist(account.pw_name,account.pw_gid),"SOURCE_PUBLIC_SIGNER_GROUP_STOP")
    directory=K.CONFIG.parent
    library=Path("/usr/local/libexec/flop-r1154")
    unit=Path("/etc/systemd/system/r1154-custody.service")
    data=(H.ROOT/"packaging/oracle/r1154-custody.service").read_bytes()
    H.need(not directory.exists() and not library.exists() and not unit.exists() and not unit.is_symlink(),"SOURCE_PUBLIC_ALREADY_EXISTS")
    directory.mkdir(mode=0o750);os.chown(directory,0,account.pw_gid)
    H.exclusive(K.CONFIG,C.G.canonical(request));os.chown(K.CONFIG,0,account.pw_gid);os.chmod(K.CONFIG,0o640)
    H.need(K.CONFIG.stat().st_gid==account.pw_gid and not stat.S_IMODE(K.CONFIG.stat().st_mode)&0o007,"SOURCE_PUBLIC_GROUP_STOP")
    spec=importlib.util.spec_from_file_location("r1155_source_public_transfer",Path(__file__).with_name("r1155_transfer.py"))
    transport=importlib.util.module_from_spec(spec);sys.modules[spec.name]=transport;spec.loader.exec_module(transport)
    library.mkdir(mode=0o755)
    for name,text in transport.bundle().items():
        path=library/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
        H.exclusive(path,text.encode());os.chmod(path,0o644)
    H.exclusive(unit,data);os.chmod(unit,0o644)
    H.Linux().command(["/usr/bin/systemctl","daemon-reload"])
    return dict(code="SOURCE_PUBLIC_CONFIG_INSTALLED_NO_SERVICE_START")


def main():
    password=None
    try:
        H.need(sys.argv[1:] in (["--recipient-init"],["--source-public-install"]),"CUSTODY_SETUP_ARGUMENT_STOP")
        if sys.argv[1:]==["--source-public-install"]:
            request=S.secured(Path("/etc/flop-r1155-source/request.json"))
            anchor=S.secured(Path("/etc/flop-r1155-source/authority.json"));H.shape(anchor,"sha")
            result=install_source_public(request,C.digest(anchor["sha"]))
        else:
            import getpass
            H.need(sys.platform=="linux" and sys.stdin.isatty(),"RECIPIENT_LOCAL_TTY_REQUIRED")
            import pwd
            H.need(os.geteuid()==pwd.getpwnam("technocore-signer").pw_uid and
                hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()==H.B.K137,"RECIPIENT_LOCAL_SIGNER_REQUIRED")
            request=S.secured(Path("/etc/flop-r1155-admission/recipient.json"))
            H.shape(request,"enrollment enrollment_sha run_id owner witness")
            a=H.Authority(request["enrollment"],request["enrollment_sha"])
            binding=dict(destination=a.trust.context["destination"],run_id=request["run_id"],purpose="ENCRYPTED_RECIPIENT_ONLY_NOT_NEW_DID")
            for field,role in (("owner","owner"),("witness","independent")):
                H.need(a.trust.verify(request[field],"r1155-recipient-init",role,int(time.time()),age=900)==binding,"RECIPIENT_APPROVAL_STOP")
            with warnings.catch_warnings():
                warnings.simplefilter("error",getpass.GetPassWarning)
                password=bytearray(getpass.getpass("LOCAL recipient encryption password (32+ bytes; NOT DID seed): ").encode())
            result=recipient_init(a,password)
        print(C.G.canonical(result).decode());return 0
    except Exception:
        print('{"code":"CUSTODY_SETUP_STOP","cutover":"NO_GO"}');return 42
    finally:
        if password is not None:password[:]=b"\0"*len(password)


if __name__=="__main__":raise SystemExit(main())
