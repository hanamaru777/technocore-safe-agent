#!/usr/bin/env bash
# Issue #371: read-only Oracle Cloud Agent -> Oracle services connectivity diagnosis.
# Public-safe output only: no OCIDs, IP addresses, request IDs, raw logs, proxy values, or secrets.
set -u
umask 077

OCA=snap.oracle-cloud-agent.oracle-cloud-agent.service
UPD=snap.oracle-cloud-agent.oracle-cloud-agent-updater.service
IMDS_URL=http://169.254.169.254/opc/v2/instance/

TMPDIR=$(mktemp -d /tmp/issue371.XXXXXX)
cleanup() {
  rm -rf -- "$TMPDIR"
}
trap cleanup EXIT

echo '=== ISSUE371 OCA ORACLE-SERVICES READ-ONLY DIAGNOSTIC ==='
echo "UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

echo '--- OCA SNAP / SERVICES ---'
snap list oracle-cloud-agent >"$TMPDIR/snap-list.txt" 2>&1
echo "SNAP_LIST_RC=$?"
python3 - "$TMPDIR/snap-list.txt" <<'PY'
from pathlib import Path
import sys
rows=[line.split() for line in Path(sys.argv[1]).read_text("utf-8",errors="replace").splitlines() if line.strip()]
if len(rows)>=2 and len(rows[1])>=3:
    print("OCA_VERSION="+rows[1][1])
    print("OCA_REVISION="+rows[1][2])
else:
    print("OCA_VERSION=UNAVAILABLE")
    print("OCA_REVISION=UNAVAILABLE")
PY

for svc in "$OCA" "$UPD"; do
  active=$(systemctl is-active "$svc" 2>/dev/null || true)
  enabled=$(systemctl is-enabled "$svc" 2>/dev/null || true)
  pid=$(systemctl show "$svc" -p MainPID --value 2>/dev/null || true)
  restarts=$(systemctl show "$svc" -p NRestarts --value 2>/dev/null || true)
  result=$(systemctl show "$svc" -p Result --value 2>/dev/null || true)
  echo "SERVICE=$svc ACTIVE=${active:-UNKNOWN} ENABLED=${enabled:-UNKNOWN} PID=${pid:-UNKNOWN} NRESTARTS=${restarts:-UNKNOWN} RESULT=${result:-UNKNOWN}"
done

echo '--- DEFAULT ROUTE / PROXY PRESENCE ---'
python3 - <<'PY'
from pathlib import Path
present=False
try:
    for line in Path("/proc/net/route").read_text("utf-8",errors="replace").splitlines()[1:]:
        fields=line.split()
        if len(fields)>=8 and fields[1]=="00000000" and fields[7]=="00000000":
            present=True
            break
except Exception:
    pass
print("DEFAULT_ROUTE_PRESENT="+("YES" if present else "NO"))
PY

for svc in "$OCA" "$UPD"; do
  systemctl show "$svc" -p Environment --value >"$TMPDIR/$(basename "$svc").env" 2>/dev/null || true
done

python3 - "$TMPDIR" <<'PY'
import pathlib,re,sys
root=pathlib.Path(sys.argv[1])
for path in sorted(root.glob("*.env")):
    text=path.read_text("utf-8",errors="replace")
    label="OCA" if "updater" not in path.name else "UPDATER"
    for key in ("http_proxy","https_proxy","no_proxy"):
        found=bool(re.search(rf"(?i)(?:^|\s){re.escape(key)}=",text))
        print(f"{label}_PROXY_{key.upper()}_SET="+("YES" if found else "NO"))
PY

echo '--- IMDS / REGION ---'
IMDS_CODE=$(curl -sS --connect-timeout 3 --max-time 5   -H 'Authorization: Bearer Oracle'   -o "$TMPDIR/imds.json"   -w '%{http_code}' "$IMDS_URL" 2>/dev/null || true)
echo "ROOT_IMDS_HTTP=${IMDS_CODE:-000}"

python3 - "$TMPDIR/imds.json" "$TMPDIR/region.txt" <<'PY'
import json,pathlib,sys
source=pathlib.Path(sys.argv[1]); out=pathlib.Path(sys.argv[2])
try:
    doc=json.loads(source.read_text("utf-8"))
except Exception:
    print("IMDS_REGION_PARSE=FAIL")
    raise SystemExit
region=doc.get("region") or doc.get("canonicalRegionName")
if isinstance(region,str) and region:
    out.write_text(region,encoding="utf-8")
    out.chmod(0o600)
    print("IMDS_REGION_PARSE=PASS")
else:
    print("IMDS_REGION_PARSE=FAIL")
PY

echo '--- OCA PROCESS ROLES ---'
MAIN_PID=$(systemctl show "$OCA" -p MainPID --value 2>/dev/null || true)
python3 - "$MAIN_PID" <<'PY'
import pathlib,pwd,sys
try:
    root=int(sys.argv[1])
except Exception:
    print("OCA_PROCESS_TREE=UNAVAILABLE")
    raise SystemExit

def stat(pid):
    try:
        raw=pathlib.Path(f"/proc/{pid}/stat").read_text("utf-8")
        right=raw.rfind(")")
        comm=raw[raw.find("(")+1:right]
        fields=raw[right+2:].split()
        ppid=int(fields[1])
        uid=None
        for line in pathlib.Path(f"/proc/{pid}/status").read_text("utf-8",errors="replace").splitlines():
            if line.startswith("Uid:"):
                uid=int(line.split()[1]); break
        user=pwd.getpwuid(uid).pw_name if uid is not None else "UNKNOWN"
        return {"pid":pid,"ppid":ppid,"comm":comm[:80],"user":user[:80]}
    except Exception:
        return None

stats={}
for proc in pathlib.Path("/proc").iterdir():
    if proc.name.isdigit():
        item=stat(int(proc.name))
        if item: stats[item["pid"]]=item

seen={root}; frontier=[root]; targets=[root]
while frontier:
    parent=frontier.pop(0)
    for pid,item in stats.items():
        if item["ppid"]==parent and pid not in seen:
            seen.add(pid); frontier.append(pid); targets.append(pid)

for pid in targets:
    item=stats.get(pid)
    if item:
        role="MAIN" if pid==root else "DESCENDANT"
        print(f"OCA_PROC ROLE={role} USER={item['user']} COMM={item['comm']}")
PY

echo '--- RECENT LOG CLASSIFICATION / ORACLE HOST DISCOVERY ---'
journalctl -u "$OCA" -u "$UPD" --since '-8 hours' --no-pager --output=cat >"$TMPDIR/journal.log" 2>/dev/null || true

python3 - "$TMPDIR/journal.log" "$TMPDIR/hosts.txt" <<'PY'
import os,pathlib,re,sys
journal=pathlib.Path(sys.argv[1])
hosts_out=pathlib.Path(sys.argv[2])
chunks=[]
try:
    chunks.append(journal.read_text("utf-8",errors="replace"))
except Exception:
    pass

roots=[
    pathlib.Path("/var/snap/oracle-cloud-agent/common/log"),
    pathlib.Path("/var/log/oracle-cloud-agent"),
]
files=[]
for root in roots:
    if not root.exists(): continue
    for current,dirs,names in os.walk(root):
        rel=len(pathlib.Path(current).parts)-len(root.parts)
        if rel>=6: dirs[:]=[]
        for name in names:
            if name.lower().endswith(".log"):
                files.append(pathlib.Path(current)/name)
        if len(files)>=40: break
    if len(files)>=40: break

for path in files[:40]:
    try:
        with path.open("rb") as fh:
            fh.seek(0,2); size=fh.tell(); fh.seek(max(0,size-524288))
            chunks.append(fh.read().decode("utf-8","replace"))
    except Exception:
        pass

text="\n".join(chunks).lower()
patterns={
    "AUTH_401":("status code: 401","http status code: 401","notauthenticated"),
    "AUTH_403":("status code: 403","http status code: 403","notauthorized"),
    "HTTP_404":("status code: 404","http status code: 404"),
    "HTTP_5XX":("status code: 500","status code: 502","status code: 503","status code: 504"),
    "TIMEOUT":("timeout","timed out","deadline exceeded"),
    "DNS":("no such host","name resolution","temporary failure in name resolution"),
    "CONNECT":("connection refused","no route to host","network is unreachable","connection reset"),
    "TLS":("x509","tls handshake","certificate verify","certificate signed"),
    "SUCCESS_200":("status: 200","status 200","200 ok"),
    "RUNCOMMAND":("runcommand","run command"),
}
for label,needles in patterns.items():
    print("LOG_CLASS_"+label+"="+str(sum(text.count(n) for n in needles)))

host_re=re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:oraclecloud\.com|oci\.oraclecloud\.com)\b")
hosts=sorted({m.group(0).lower().rstrip(".") for m in host_re.finditer(text)})
hosts=hosts[:12]
hosts_out.write_text("\n".join(hosts),encoding="utf-8")
hosts_out.chmod(0o600)
print("ORACLE_HOSTS_DISCOVERED="+str(len(hosts)))
for host in hosts:
    print("ORACLE_HOST="+host)
PY

echo '--- BOUNDED DNS / TCP443 / TLS PROBES ---'
python3 - "$TMPDIR/hosts.txt" "$TMPDIR/region.txt" <<'PY'
import pathlib,socket,ssl,sys

hosts=[]
host_path=pathlib.Path(sys.argv[1])
if host_path.exists():
    hosts.extend(x.strip() for x in host_path.read_text("utf-8").splitlines() if x.strip())

region_path=pathlib.Path(sys.argv[2])
if region_path.exists():
    region=region_path.read_text("utf-8").strip()
    if region:
        hosts.extend([
            f"iaas.{region}.oraclecloud.com",
            f"telemetry-ingestion.{region}.oraclecloud.com",
            f"monitoring.{region}.oraclecloud.com",
            f"auth.{region}.oraclecloud.com",
        ])

dedup=[]
for h in hosts:
    if h and h not in dedup:
        dedup.append(h)

for host in dedup[:16]:
    dns="NO"; tcp="NO"; tls="NO"; err="NONE"
    try:
        socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)
        dns="YES"
        with socket.create_connection((host,443),timeout=3) as sock:
            tcp="YES"
            ctx=ssl.create_default_context()
            with ctx.wrap_socket(sock,server_hostname=host):
                tls="YES"
    except Exception as exc:
        err=type(exc).__name__
    print(f"CONNECTIVITY HOST={host} DNS={dns} TCP443={tcp} TLS={tls} ERROR_CLASS={err}")
PY

echo '--- SAFETY TAIL ---'
echo 'MUTATION_COMMANDS=NONE'
echo 'SERVICE_RESTART=NO'
echo 'NETWORK_CHANGE=NO'
echo 'FIREWALL_CHANGE=NO'
echo 'ROUTE_CHANGE=NO'
echo 'PROXY_CHANGE=NO'
echo 'AGENT_CONFIG_CHANGE=NO'
echo 'RUN_COMMAND_CREATED=NO'
echo 'PACKAGE_INSTALL=NO'
echo 'ACTIVE_CAPTURE_SQLITE_QUERY=NO'
echo 'RAW_LOG_OUTPUT=NO'
echo 'OCID_OUTPUT=NO'
echo 'IP_OUTPUT=NO'
echo '=== ISSUE371_DIAGNOSTIC=COMPLETE_READ_ONLY ==='
