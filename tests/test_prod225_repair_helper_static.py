from pathlib import Path


SCRIPT = Path("packaging/oracle/run-prod225-repair.sh")


def test_prod225_repair_is_exact_and_bounded():
    text = SCRIPT.read_text("utf-8")
    assert "PRE=362dddadb669d4e126fe00c37da4a3f57cecbdbc" in text
    assert "TARGET=11c527796d468beb268a1da1538be3a03cb88c33" in text
    assert "gitx merge --ff-only" in text
    assert "systemctl restart \"$RES\"" in text
    assert "systemctl restart \"$CAP\"" not in text
    assert "systemctl restart \"$SIG\"" not in text
    assert "systemctl restart \"$DIS\"" not in text
    assert "timeout 8s python3" in text
    assert "timeout 30s sudo -u" in text
    assert "lobby-capture-service.sqlite3" not in text
    assert "health=ok before" not in text
    assert "PROD225_REPAIR=PASS" in text
    assert "DO_NOT_RERUN=YES" in text


def test_prod225_repair_preserves_protected_core_baseline():
    text = SCRIPT.read_text("utf-8")
    assert '[[ "$PRE_CE" == 117 && "$PRE_CM" == 5083155 ]]' in text
    assert '[[ "$POST_CE" == 117 && "$POST_CM" == 5083155 ]]' in text
