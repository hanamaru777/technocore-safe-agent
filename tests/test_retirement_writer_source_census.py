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
    m.inventory(folder)
    (folder / "new-finance-signer.service").write_text(
        "[Service]\nExecStart=/usr/bin/anything\n")
    with pytest.raises(m.Stop, match="UNREVIEWED_SERVICE_OR_TIMER_STOP"):
        m.inventory(folder)

def test_future_removed_service_requires_review(tmp_path):
    m = load()
    for filename in m.REVIEWED_UNITS:
        (tmp_path / filename).write_text(
            "[Service]\nExecStart=/bin/true\nEnvironment=FLOP_STATE_DIR=/var/lib/technocore-safe-agent\n"
            if filename.endswith(".service") else
            "[Timer]\nOnBootSec=20\n")
    (tmp_path / "technocore-safe-agent-signer.service").unlink()
    with pytest.raises(m.Stop, match="UNREVIEWED_SERVICE_OR_TIMER_STOP"):
        m.inventory(tmp_path)

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
        m.inventory(tmp_path)

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

def test_no_environment_activity_or_cloud_runtime():
    data = SRC.read_text()
    compile(data, str(SRC), "exec")
    for disallowed in ("subprocess", "import oci", "requests", "urllib",
                       "systemctl", "os.system(", "os.kill(", "os.chmod(",
                       "shutil.copy(", "write_bytes(", "write_text("):
        # inspect source alone; tests intentionally write synthetic files.
        assert disallowed not in data
    assert "FLOP_R865_SOURCE_WRITER_EPOCH_NOT_PROVEN" in data
