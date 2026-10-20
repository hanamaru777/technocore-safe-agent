"""Pinned-source and synthetic remote metadata only; no SSH/network invocation."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packaging/oracle/r1024_cloudshell_unit_identity_witness.py"
PROBE = ROOT / "packaging/oracle/r1023_unit_identity_readonly.py"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load("r1024", SCRIPT)
guest = load("r1023_fixture", PROBE)


def source():
    # Model the immutable Git blob downloaded by GitHub, irrespective of checkout EOL.
    return PROBE.read_bytes().replace(b"\r\n", b"\n")


def report():
    installed = guest.metadata_names(guest.PREFIX + "signer.service enabled\n")
    live = guest.metadata_names(guest.PREFIX + "signer.service loaded active running\n", live=True)
    return guest.analyze_units(installed, live)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def test_commit_blob_and_download_pin():
    content = source()
    assert m.COMMIT == "4f78fc8b4afb14604792e5b2f07f1fecdc131736"
    assert hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest() == m.BLOB_SHA
    def fetch(url, timeout):
        assert m.COMMIT in url and url.endswith("/r1023_unit_identity_readonly.py")
        assert timeout == 15
        return io.BytesIO(content)
    assert m.checked_source(fetcher=fetch) == content
    assert m.inspect_output(encoded(report()), content) == report()


@pytest.mark.parametrize("payload", [b"old-probe", b"tampered-source", b"x" * 32770],
                         ids=["old", "tampered", "oversize"])
def test_wrong_or_oversized_source_fails_before_ssh(payload):
    with pytest.raises(m.Stop):
        m.checked_source(fetcher=lambda url, timeout: io.BytesIO(payload))


def test_unverified_source_cannot_enter_ssh_command(tmp_path):
    with pytest.raises(m.Stop, match="PINNED_PROBE_BLOB_STOP"):
        m.ssh_args(b"arbitrary-code", tmp_path / "key", tmp_path / "hosts")


def test_pinned_ssh_identity_and_bounded_readonly_invocation(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(m.Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(m, "private_custody",
                        lambda file, **kw: calls.append((file.name, kw)))
    def executor(args, **kwargs):
        assert args[:4] == ["ssh", "-F", "/dev/null", "-T"]
        for option in ("StrictHostKeyChecking=yes", "HostKeyAlgorithms=ecdsa-sha2-nistp256",
                       "ClearAllForwardings=yes", "PasswordAuthentication=no",
                       "KbdInteractiveAuthentication=no", "BatchMode=yes", "IdentitiesOnly=yes",
                       "IdentityAgent=none", "PermitLocalCommand=no"):
            assert option in args
        assert args[-2] == "ubuntu@" + m.HOST
        assert args[-1].startswith("sudo -n /usr/bin/python3 -c ")
        assert kwargs["stderr"] == m.subprocess.DEVNULL
        assert kwargs["input"] is None and kwargs["timeout"] <= 58
        return SimpleNamespace(returncode=0, stdout=encoded(report()))
    assert m.bounded_invoke(source(), executor=executor) == encoded(report())
    assert calls == [("new-operator-ecdsa", {}), ("known_hosts", {"allow_readable": True})]


def test_custody_owner_permissions_and_symlink_rejection(monkeypatch):
    monkeypatch.setattr(m.os, "geteuid", lambda: 17, raising=False)
    file = Path.cwd() / "synthetic-parent" / "synthetic-key"
    parent = SimpleNamespace(st_mode=m.stat.S_IFDIR | 0o700, st_uid=17)
    key = SimpleNamespace(st_mode=m.stat.S_IFREG | 0o600, st_uid=17, st_nlink=1, st_size=10)
    monkeypatch.setattr(m.os, "lstat", lambda path: parent if path == file.parent else key)
    m.private_custody(file)
    key.st_mode = m.stat.S_IFREG | 0o644
    with pytest.raises(m.Stop, match="CUSTODY_FILE_STOP"):
        m.private_custody(file)
    key.st_mode = m.stat.S_IFLNK | 0o600
    with pytest.raises(m.Stop, match="CUSTODY_FILE_STOP"):
        m.private_custody(file)
    key.st_mode = m.stat.S_IFREG | 0o600
    key.st_uid = 18
    with pytest.raises(m.Stop, match="CUSTODY_FILE_STOP"):
        m.private_custody(file)


@pytest.mark.parametrize("change", [
    lambda r: r.pop("flags"),
    lambda r: r["flags"].update(all_writers_fenced="YES"),
    lambda r: r["flags"].update(oci_retirement="GO"),
    lambda r: r["units"][0].update(identity="unsafe-unit@secret.service"),
    lambda r: r["units"][0].update(known=False),
    lambda r: r["units"][0].update(active_states=["unrecognized"]),
    lambda r: r["units"].append(dict(r["units"][0])),
    lambda r: r.update(missing_known=[]),
    lambda r: r.update(active_signer_candidates=[]),
    lambda r: r.update(unexpected="synthetic-secret"),
])
def test_missing_forged_or_inconsistent_response_rejected(change):
    value = report()
    change(value)
    with pytest.raises(m.Stop):
        m.inspect_output(encoded(value), source())


@pytest.mark.parametrize("raw", [b"x" * 65537, b"not-json\n", b"\xff\n",
                                  b'{"schema_version":1,"schema_version":2}\n'],
                         ids=["oversize", "not-json", "nonascii", "duplicate-key"])
def test_malformed_and_oversized_output_rejected(raw):
    with pytest.raises(m.Stop):
        m.inspect_output(raw, source())


def test_safe_guest_stop_and_no_raw_output(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(m.Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(m, "private_custody", lambda *args, **kwargs: None)
    for payload, expected in ((b"FLOP_R1023_STOP=WRONG_GUEST_SCOPE\n", "ORIGINAL_GUEST_WRONG_GUEST_SCOPE"),
                              (b"synthetic-secret-raw-data", "PINNED_GUEST_COMMAND_EXIT_STOP")):
        with pytest.raises(m.Stop, match=expected):
            m.bounded_invoke(source(), executor=lambda *args, **kwargs:
                             SimpleNamespace(returncode=42, stdout=payload))
    assert capsys.readouterr().out == ""


def test_wrapper_prints_validated_summary_only(monkeypatch, capsys):
    monkeypatch.setattr(m, "preflight", lambda: None)
    monkeypatch.setattr(m, "checked_source", source)
    monkeypatch.setattr(m, "bounded_invoke", lambda content: encoded(report()))
    m.run()
    output = capsys.readouterr().out
    assert "STRICT_NO_GO" in output and "NO_WRITER_EPOCH_PROVEN=YES" in output
    assert "all_writers_fenced" in output
    assert m.HOST not in output and m.KEY_DIR not in output


def test_no_mutating_or_sensitive_primitives():
    raw = SCRIPT.read_text(encoding="utf-8")
    for forbidden in ("systemctl stop", "systemctl start", "systemctl restart", "systemctl disable",
                      "systemctl mask", "sqlite3", "journalctl", "os.environ", ".write_text(",
                      ".write_bytes(", "print(result.stdout)", "print(raw)", "urlopen("):
        assert forbidden not in raw

