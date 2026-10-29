"""R1097 fixed AWS CloudShell-to-Lightsail SSH transport, no old census replay."""
from pathlib import Path
import re
import subprocess
ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"packaging/migration/r1097_aws_cloudshell_k137_flop_readonly.sh"

def test_shell_syntax_and_fixed_one_guest():
    p=subprocess.run(["bash","-n",str(SCRIPT)],capture_output=True,text=True)
    assert p.returncode==0,p.stderr
    s=SCRIPT.read_text(encoding="utf8")
    assert "aws lightsail get-instance-access-details" in s
    assert "--instance-name tradebot-k137 --protocol ssh --region ap-northeast-1" in s
    assert 'and user=="ubuntu"' in s
    assert 'StrictHostKeyChecking=yes' in s
    assert 'IdentityAgent=none' in s
    assert 'PasswordAuthentication=no' in s
    assert 'K137_SSH_OR_READONLY_STOP' in s
    assert '"/usr/bin/python3 -I -B -"' in s
    assert '<"$d/r1096.py"' in s
    assert "r1096_k137_flop_storage_readonly.py" in s
    assert "d799e594ec48ac5e313f389ac895823df7342067" in s
    assert "r1067_aws_cloudshell_k137_readonly.sh" not in s

def test_no_production_mutations_or_raw_key_output():
    s=SCRIPT.read_text(encoding="utf8")
    for bad in ["sudo ", "systemctl ", "rm -rf", "--delete",
                "scp ", "rsync ", "curl |", "ssh-keyscan",
                "tradebot-k137-private", "tradebot_k137.py",
                "autopilot-audit", "Get-R1027"]:
        assert bad not in s,bad
    assert "privateKey" in s and 'put("identity",private.strip()+"\\n")' in s
    assert "print(private)" not in s
    assert '"$d/r1096.py"' in s
    assert "trap cleanup EXIT" in s
    assert s.count("ssh -F /dev/null -T -i") == 1
