"""R1017 synthetic Cloud Shell original-OCI witness; no SSH or network calls."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packaging/oracle/r1017_cloudshell_writer_witness.py"
ORIGINAL_PROBE = ROOT / "packaging/oracle/r1016_writer_inventory_readonly.py"
SPEC = importlib.util.spec_from_file_location("r1017_cloudshell_writer_witness", SCRIPT)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


@pytest.fixture(autouse=True)
def _provide_posix_euid_on_windows(monkeypatch):
    monkeypatch.setattr(m.os, "geteuid", lambda: 0, raising=False)
    if os.name != "nt":
        return
    native_lstat = m.os.lstat

    def posix_lstat(path):
        native = native_lstat(path)
        candidate = Path(path)
        is_dir = candidate.is_dir()
        permissions = 0o700 if is_dir else (0o644 if candidate.name == "operator" else 0o600)
        return SimpleNamespace(
            st_mode=(m.stat.S_IFDIR if is_dir else m.stat.S_IFREG) | permissions,
            st_uid=0,
            st_nlink=1,
            st_size=native.st_size,
        )

    monkeypatch.setattr(m.os, "lstat", posix_lstat)


def pinned_probe_content():
    return ORIGINAL_PROBE.read_bytes().replace(b"\r\n", b"\n")


def valid_result():
    entries = {key: "0" for key in m.EXPECTED_KEYS}
    entries["FLOP_R1016_STATIC_SERVICE_COUNT"] = "19"
    entries["FLOP_R1016_STATIC_TIMER_COUNT"] = "8"
    entries.update(dict(m.EXPECTED_FLAGS))
    return ("".join(f"{key}={entries[key]}\n" for key in sorted(entries))).encode()


def test_source_is_exactly_pinned_original_probe_without_network():
    content = pinned_probe_content()
    asserted = hashlib.sha1(
        b"blob " + str(len(content)).encode("ascii") + b"\0" + content
    ).hexdigest()
    assert asserted == m.BLOB_SHA
    assert m.COMMIT == "d8a53427d75de40471dda30d056d9cc7a99ec953"
    assert m.EXPECTED_ORIGINAL.encode() in content
    assert "FLOP_R1016_OVERSIZED_CMDLINE_PROCESSES" in m.EXPECTED_KEYS
    assert "FLOP_R1016_OVERSIZED_CGROUP_PROCESSES" in m.EXPECTED_KEYS
    assert m.checked_source(fetcher=lambda url, timeout: io.BytesIO(content)) == content


def test_changed_downloaded_source_rejected_before_ssh():
    content = pinned_probe_content()
    with pytest.raises(m.Stop, match="PINNED_PROBE_BLOB_STOP"):
        m.checked_source(fetcher=lambda url, timeout:
                         io.BytesIO(content.replace(b"STATE =", b"STATE_ =", 1)))


def test_old_probe_without_oversized_counters_is_rejected_before_ssh():
    content = pinned_probe_content()
    old = content.replace(
        b'            "oversized_cmdline_processes": oversized_cmdline,\n'
        b'            "oversized_cgroup_processes": oversized_cgroup,\n',
        b"",
        1,
    )
    assert old != content
    with pytest.raises(m.Stop, match="PINNED_PROBE_BLOB_STOP"):
        m.checked_source(fetcher=lambda url, timeout: io.BytesIO(old))


def test_source_oversize_fails_even_with_streaming_response():
    with pytest.raises(m.Stop, match="PROBE_SOURCE_OVERSIZE_STOP"):
        m.checked_source(fetcher=lambda url, timeout:
                         io.BytesIO(b"x" * (m.SOURCE_MAX + 10)))


def test_ssh_whitelist_preserves_prior_operator_custody(tmp_path, monkeypatch):
    parent = tmp_path / m.KEY_DIR
    parent.mkdir(mode=0o700)
    key = parent / "new-operator-ecdsa"
    hosts = parent / "known_hosts"
    key.write_bytes(b"synthetic-private-operator-key")
    key.chmod(0o600)
    hosts.write_bytes(b"synthetic-original-known-host")
    hosts.chmod(0o600)
    monkeypatch.setattr(m.Path, "home", staticmethod(lambda: tmp_path))
    plain = b"print('synthetic-only')"
    def fake_call(args, stdout, stderr, input, check, timeout):
        assert args[0:4] == ["ssh", "-F", "/dev/null", "-T"]
        assert "StrictHostKeyChecking=yes" in args
        assert "HostKeyAlgorithms=ecdsa-sha2-nistp256" in args
        assert "IdentityAgent=none" in args
        assert "ClearAllForwardings=yes" in args
        assert "PasswordAuthentication=no" in args
        assert "KbdInteractiveAuthentication=no" in args
        assert args[-2] == "ubuntu@" + m.HOST
        assert "sudo -n /usr/bin/python3 -c" in args[-1]
        assert "systemctl stop" not in args[-1]
        assert timeout <= 58
        return SimpleNamespace(returncode=0, stdout=valid_result())
    assert m.bounded_invoke(plain, executor=fake_call) == valid_result()


def test_custody_refuses_world_readable_private_key(tmp_path):
    base = tmp_path / "private"
    base.mkdir(mode=0o700)
    key = base / "operator"
    key.write_bytes(b"fixture")
    key.chmod(0o644)
    with pytest.raises(m.Stop, match="CUSTODY_FILE_STOP"):
        m.private_custody(key)


def test_original_or_k137_host_paths_refuse_preflight(monkeypatch):
    monkeypatch.setattr(m.sys, "platform", "linux")
    monkeypatch.setattr(m.os, "geteuid", lambda: 10001)
    original_exists = m.Path.exists
    original_symlink = m.Path.is_symlink
    for unsafe in ("/opt/technocore-safe-agent", "/opt/tradebot-k137-private",
                   "/opt/flop-shadow"):
        with monkeypatch.context() as patch:
            patch.setattr(m.Path, "exists",
                          lambda self: str(self).replace("\\", "/") == unsafe
                          or original_exists(self))
            patch.setattr(m.Path, "is_symlink",
                          lambda self: (str(self).replace("\\", "/") == unsafe and False)
                          or original_symlink(self))
            with pytest.raises(m.Stop, match="LIVE_HOST_REFUSED"):
                m.preflight()


def test_accept_exact_aggregate_flags_but_never_claim_quiescence():
    parsed = m.inspect_output(valid_result())
    assert parsed["FLOP_R1016_STATIC_SERVICE_COUNT"] == "19"
    assert parsed["FLOP_R1016_ALL_WRITERS_FENCED"] == "NO"
    assert parsed["FLOP_R1016_SIGNER_INFLIGHT_POST_RESOLVED"] == "NO"


def test_missing_oversized_count_is_rejected():
    raw = valid_result()
    missing = raw.replace(b"FLOP_R1016_OVERSIZED_CMDLINE_PROCESSES=0\n", b"", 1)
    with pytest.raises(m.Stop, match="RESPONSE_LINE_COUNT_STOP"):
        m.inspect_output(missing)


@pytest.mark.parametrize("update", (
    lambda b: b.replace(b"=19\n", b"=20\n", 1),
    lambda b: b.replace(b"=NO\n", b"=YES\n", 1),
    lambda b: b.replace(b"=0\n", b"=01\n", 1),
    lambda b: b + b"FLOP_R1016_OTHER=0\n",
    lambda b: b[:-1],
    lambda b: b.replace(b"=0\n", b"=\xff\n", 1),
))
def test_wrong_or_ambiguous_remote_response_fails_closed(update):
    with pytest.raises(m.Stop):
        m.inspect_output(update(valid_result()))


def test_remote_nonzero_exit_never_prints_remote_stderr(tmp_path, monkeypatch):
    base = tmp_path / m.KEY_DIR
    base.mkdir(mode=0o700)
    for f in ("new-operator-ecdsa", "known_hosts"):
        p = base / f
        p.write_bytes(b"fake")
        p.chmod(0o600)
    monkeypatch.setattr(m.Path, "home", staticmethod(lambda: tmp_path))
    def failed(args, **kw):
        return SimpleNamespace(returncode=255, stdout=b"remote-data-should-not-print")
    with pytest.raises(m.Stop, match="PINNED_SSH_AUTH_OR_NETWORK_STOP"):
        m.bounded_invoke(b"safe", executor=failed)


def test_missing_custody_files_yield_only_fixed_public_codes(tmp_path):
    parent = tmp_path / "private"
    with pytest.raises(m.Stop, match="CUSTODY_PARENT_MISSING_STOP"):
        m.private_custody(parent / "missing")
    parent.mkdir(mode=0o700)
    with pytest.raises(m.Stop, match="CUSTODY_FILE_MISSING_STOP"):
        m.private_custody(parent / "missing")


@pytest.mark.parametrize(("code", "output", "expected"), (
    (42, b"FLOP_R1016_STOP=ORIGINAL_HEAD_MISMATCH_STOP\n",
     "ORIGINAL_GUEST_ORIGINAL_HEAD_MISMATCH_STOP"),
    (42, b"FLOP_R1016_STOP=PROC_ACCESS_STOP\r\n",
     "ORIGINAL_GUEST_PROC_ACCESS_STOP"),
    (42, b"unsafe-text\0private-data", "PINNED_GUEST_COMMAND_EXIT_STOP"),
    (1, b"remote-message-that-must-not-be-shown", "PINNED_GUEST_COMMAND_EXIT_STOP"),
))
def test_guest_exit_classified_without_raw_stdout(tmp_path, monkeypatch, code, output, expected):
    parent = tmp_path / m.KEY_DIR
    parent.mkdir(mode=0o700)
    for name in ("new-operator-ecdsa", "known_hosts"):
        file = parent / name
        file.write_bytes(b"fixture")
        file.chmod(0o600)
    monkeypatch.setattr(m.Path, "home", staticmethod(lambda: tmp_path))
    def fake_executor(args, **kw):
        return SimpleNamespace(returncode=code, stdout=output)
    with pytest.raises(m.Stop, match=expected) as error:
        m.bounded_invoke(b"only-synthetic-source", executor=fake_executor)
    assert b"private-data" not in str(error.value).encode()


def test_static_no_mutating_calls_and_output_never_raw_response():
    src = SCRIPT.read_text()
    compile(src, str(SCRIPT), "exec")
    for forbidden in (
        "systemctl stop", "systemctl restart", "systemctl disable",
        "subprocess.Popen(", "os.unlink(", "os.remove(",
        "sudo systemctl", "AWS_ACCESS_KEY", "print(result.stdout)",
    ):
        assert forbidden not in src
    assert "RESPONSE_SAFETY_FLAG_STOP" in src
    assert "NO_WRITER_EPOCH_PROVEN=YES" in src
