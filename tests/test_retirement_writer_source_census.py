"""R865 offline source-unit full writer entrypoint census, no cloud calls."""
import importlib.util
from pathlib import Path
import pytest

SRC = Path(__file__).resolve().parents[1] / "packaging" / "archive" / "retirement_writer_source_census.py"

def load():
    spec = importlib.util.spec_from_file_location("flop_r865", SRC)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def test_real_main_packaging_unit_set_is_complete():
    m = load()
    folder = SRC.parents[2] / "packaging" / "oracle"
    result = m.inventory(folder)
    assert result["unit_sources"] == len(m.REVIEWED_UNITS)
    assert result["timer_sources"] >= 5
    assert result["potential_state_writer_sources"] >= 8
    assert len(result["unit_registry_sha256"]) == 64

def test_future_unregistered_service_fails_closed(tmp_path):
    m = load()
    folder = tmp_path
    for filename in m.REVIEWED_UNITS:
        (folder / filename).write_text(
            "[Service]\nExecStart=/bin/true\nEnvironment=FLOP_STATE_DIR=/var/lib/technocore-safe-agent\n"
            if filename.endswith(".service") else
            "[Timer]\nOnBootSec=20\n")
    m.inventory(folder, enforce_pinned=False)
    (folder / "new-finance-signer.service").write_text(
        "[Service]\nExecStart=/usr/bin/anything\n")
    with pytest.raises(m.Stop, match="UNREVIEWED_SERVICE_OR_TIMER_STOP"):
        m.inventory(folder, enforce_pinned=False)

def test_future_removed_service_requires_review(tmp_path):
    m = load()
    for filename in m.REVIEWED_UNITS:
        (tmp_path / filename).write_text(
            "[Service]\nExecStart=/bin/true\nEnvironment=FLOP_STATE_DIR=/var/lib/technocore-safe-agent\n"
            if filename.endswith(".service") else
            "[Timer]\nOnBootSec=20\n")
    (tmp_path / "technocore-safe-agent-signer.service").unlink()
    with pytest.raises(m.Stop, match="UNREVIEWED_SERVICE_OR_TIMER_STOP"):
        m.inventory(tmp_path, enforce_pinned=False)

def test_writer_downgrade_cannot_silently_pass(tmp_path):
    m = load()
    for filename in m.REVIEWED_UNITS:
        (tmp_path / filename).write_text(
            "[Service]\nExecStart=/bin/true\nEnvironment=FLOP_STATE_DIR=/var/lib/technocore-safe-agent\n"
            if filename.endswith(".service") else
            "[Timer]\nOnBootSec=20\n")
    (tmp_path / "technocore-safe-agent-signer.service").write_text(
        "[Service]\nExecStart=/bin/true\n")
    with pytest.raises(m.Stop, match="PINNED_WRITER_CHANGED_STOP"):
        m.inventory(tmp_path, enforce_pinned=False)

def test_unapproved_unit_config_section_rejected():
    m = load()
    with pytest.raises(m.Stop, match="UNIT_SECTION_UNKNOWN"):
        m.properties("[Path]\nPathExists=/tmp/secret\n")

def test_pinned_financial_write_services_included():
    m = load()
    assert "technocore-safe-agent-close1-approved-trade.service" in m.REQUIRE_FENCING
    assert "technocore-safe-agent-tclk-accept@.service" in m.REQUIRE_FENCING
    assert "technocore-safe-agent-signer.service" in m.REQUIRE_FENCING
    assert "resident.service" in m.REQUIRE_FENCING


def make_fake_units(folder, m):
    for name in m.REVIEWED_UNITS:
        if name.endswith(".service"):
            (folder / name).write_text(
                "[Service]\nExecStart=/bin/true\n"
                "Environment=FLOP_STATE_DIR=/var/lib/technocore-safe-agent\n")
        else:
            (folder / name).write_text("[Timer]\nOnBootSec=20\n")


def test_different_execstart_while_writer_path_unchanged_changes_digest(tmp_path):
    m = load()
    make_fake_units(tmp_path, m)
    original = m.inventory(tmp_path, enforce_pinned=False)["unit_registry_sha256"]
    file = tmp_path / "technocore-safe-agent-signer.service"
    file.write_text(file.read_text().replace("ExecStart=/bin/true",
                                             "ExecStart=/bin/false"))
    assert original != m.inventory(tmp_path, enforce_pinned=False)["unit_registry_sha256"]


def test_changed_service_environment_only_changes_digest(tmp_path):
    m = load()
    make_fake_units(tmp_path, m)
    original = m.inventory(tmp_path, enforce_pinned=False)["unit_registry_sha256"]
    file = tmp_path / "resident.service"
    file.write_text(file.read_text() +
                    "Environment=TECHNOCORE_REVISION=unsafe-change\n")
    assert original != m.inventory(tmp_path, enforce_pinned=False)["unit_registry_sha256"]


def test_explicit_timer_target_binding_and_invalid_target_stop(tmp_path):
    m = load()
    make_fake_units(tmp_path, m)
    before = m.inventory(tmp_path, enforce_pinned=False)["unit_registry_sha256"]
    timer = tmp_path / "technocore-safe-agent-tclk-stager.timer"
    timer.write_text("[Timer]\nOnBootSec=20\n"
                     "Unit=technocore-safe-agent-tclk-preparer.service\n")
    assert before != m.inventory(tmp_path, enforce_pinned=False)["unit_registry_sha256"]
    timer.write_text("[Timer]\nOnBootSec=20\n"
                     "Unit=unknown-finance-writer.service\n")
    with pytest.raises(m.Stop, match="TIMER_TARGET_UNREVIEWED_STOP"):
        m.inventory(tmp_path, enforce_pinned=False)


def test_double_timer_target_rejected(tmp_path):
    m = load()
    make_fake_units(tmp_path, m)
    timer = tmp_path / "technocore-safe-agent-tclk-stager.timer"
    timer.write_text("[Timer]\nOnBootSec=20\n"
                     "Unit=technocore-safe-agent-tclk-stager.service\n"
                     "Unit=technocore-safe-agent-tclk-preparer.service\n")
    with pytest.raises(m.Stop, match="TIMER_MULTIPLE_TARGETS_STOP"):
        m.inventory(tmp_path, enforce_pinned=False)


def test_exact_real_main_git_blob_ids_match_pinned_source():
    m = load()
    folder = SRC.parents[2] / "packaging" / "oracle"
    assert set(m.PINNED_SOURCE_BLOBS) == m.REVIEWED_UNITS
    for name, expected in m.PINNED_SOURCE_BLOBS.items():
        assert m.git_blob_id((folder / name).read_bytes()) == expected


def test_tampering_with_one_source_unit_fails_even_if_writer_reference_same(tmp_path):
    m = load()
    original = SRC.parents[2] / "packaging" / "oracle"
    for name in m.REVIEWED_UNITS:
        (tmp_path / name).write_bytes((original / name).read_bytes())
    m.inventory(tmp_path)
    victim = tmp_path / "technocore-safe-agent-signer.service"
    victim.write_bytes(victim.read_bytes() +
                       b"\n# harmless-looking changed comment\n")
    with pytest.raises(m.Stop, match="PINNED_SOURCE_UNIT_DRIFT_STOP"):
        m.inventory(tmp_path)



def test_exact_two_reviewed_source_to_installed_aliases():
    m = load()
    assert m.INSTALLED_ALIASES == {
        "technocore-safe-agent-airdrop-monitor.service": "airdrop-monitor.service",
        "technocore-safe-agent-airdrop-notifier.service": "airdrop-notifier.service",
    }
    root = SRC.parents[2] / "packaging" / "oracle"
    for installed, source in m.INSTALLED_ALIASES.items():
        path = root / source.replace(".service", ".timer")
        lines = m.properties(path.read_text())
        assert lines[("Timer", "Unit")] == [installed]


def test_third_party_installed_timer_target_cannot_pass_alias_check(tmp_path):
    m = load()
    make_fake_units(tmp_path, m)
    timer = tmp_path / "airdrop-monitor.timer"
    timer.write_text("[Timer]\nOnBootSec=30\n"
                     "Unit=technocore-safe-agent-unaudited-signer.service\n")
    with pytest.raises(m.Stop, match="TIMER_TARGET_UNREVIEWED_STOP"):
        m.inventory(tmp_path, enforce_pinned=False)


def test_no_environment_activity_or_cloud_runtime():
    data = SRC.read_text()
    compile(data, str(SRC), "exec")
    for disallowed in ("subprocess", "import oci", "requests", "urllib",
                       "systemctl", "os.system(", "os.kill(", "os.chmod(",
                       "shutil.copy(", "write_bytes(", "write_text("):
        # inspect source alone; tests intentionally write synthetic files.
        assert disallowed not in data
    assert "FLOP_R865_SOURCE_WRITER_EPOCH_NOT_PROVEN" in data
