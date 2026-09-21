from __future__ import annotations

import subprocess
from flop_agent import core

HELPER = core.ROOT / "packaging" / "oracle" / "issue371-oca-oracle-services-readonly.sh"

def _text() -> str:
    return HELPER.read_text("utf-8")

def test_issue371_helper_bash_syntax() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)

def test_issue371_helper_is_read_only() -> None:
    text=_text().lower()
    for forbidden in (
        "systemctl restart","systemctl stop","systemctl start",
        "snap refresh","snap revert","snap install","snap remove",
        "iptables -a ","iptables -i ","iptables -d ","iptables -f ",
        "ip route add","ip route del","route add","route del",
        "apt install","apt-get install","pip install","uv pip install",
        "oci compute instance update","instance-agent command create","run command create",
        "client.post(","client.put(","client.patch(","client.delete(",
        "post_signed(","write_note(",
    ):
        assert forbidden not in text
    for token in (
        "MUTATION_COMMANDS=NONE","SERVICE_RESTART=NO","NETWORK_CHANGE=NO",
        "FIREWALL_CHANGE=NO","ROUTE_CHANGE=NO","PROXY_CHANGE=NO",
        "AGENT_CONFIG_CHANGE=NO","RUN_COMMAND_CREATED=NO","PACKAGE_INSTALL=NO",
        "ACTIVE_CAPTURE_SQLITE_QUERY=NO","RAW_LOG_OUTPUT=NO","OCID_OUTPUT=NO","IP_OUTPUT=NO",
    ):
        assert token.lower() in text

def test_issue371_helper_never_queries_active_capture_sqlite() -> None:
    text=_text().lower()
    assert "sqlite3.connect" not in text
    assert "select " not in text
    assert "pragma " not in text

def test_issue371_helper_classifies_without_raw_logs() -> None:
    text=_text()
    assert "journalctl" in text
    assert '"AUTH_401":' in text
    assert '"AUTH_403":' in text
    assert '"HTTP_404":' in text
    assert '"HTTP_5XX":' in text
    assert '"TIMEOUT":' in text
    assert '"DNS":' in text
    assert '"CONNECT":' in text
    assert '"TLS":' in text
    assert '"SUCCESS_200":' in text
    assert 'print("LOG_CLASS_"+label+"="' in text
    assert 'cat "$TMPDIR/journal.log"' not in text

def test_issue371_helper_only_reports_proxy_presence() -> None:
    text=_text()
    assert "-p Environment --value" in text
    assert 'for key in ("http_proxy","https_proxy","no_proxy"):' in text
    assert 'print(f"{label}_PROXY_{key.upper()}_SET="' in text

def test_issue371_helper_bounds_oracle_connectivity_probes() -> None:
    text=_text()
    assert "ORACLE_HOSTS_DISCOVERED=" in text
    assert "CONNECTIVITY HOST=" in text
    assert "getaddrinfo" in text
    assert "create_connection" in text
    assert "wrap_socket" in text
    assert "dedup[:16]" in text
    assert "timeout=3" in text

def test_issue371_helper_does_not_print_routes_or_addresses() -> None:
    text=_text()
    assert "DEFAULT_ROUTE_PRESENT=" in text
    assert "ip route" not in text
    assert "route -n" not in text
    assert "ss -" not in text
