#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
EXPECTED_HEAD=498d332ff70cc6e5487982e27711097793a16c86
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
HB=/var/lib/technocore-safe-agent/observer/observer-heartbeat.json
SAFETY=/var/lib/technocore-safe-agent/observer-safety.json
MARKER=/var/lib/technocore-safe-agent/resident/close1-discord-runtime-activated.json
BLOCKED=/var/lib/technocore-safe-agent/resident/close1-discord-runtime-blocked.json
ACTIVATOR=/usr/local/sbin/technocore-close1-discord-activate-if-safe
UNIT=/etc/systemd/system/technocore-safe-agent-close1-discord-activation.service
TIMER=/etc/systemd/system/technocore-safe-agent-close1-discord-activation.timer

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIG=technocore-safe-agent-signer.service
DIS=technocore-safe-agent-discord.service

RES_PID=2462149
CAP_PID=2708820
SIG_PID=2462068
DIS_PID=2660066
CORE_E=143
CORE_M=5652707
BRIDGE_E=26
BRIDGE_M=569552

stop_now() {
  echo "PROD560V1=STOP:$1"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
on_error() {
  local rc=$?
  trap - ERR
  echo "PROD560V1=ERROR:rc_$rc"
  echo "DO_NOT_RERUN=YES"
  exit 0
}
trap on_error ERR

[[ $EUID -eq 0 ]] || stop_now not_root
[[ -d "$APP/.git" && -x "$PY" && -f "$OBS" && -f "$HB" && -f "$SAFETY" ]] || stop_now required_path_missing
OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || stop_now git_owner_missing
git_owner() { runuser -u "$OWNER" -- git -C "$APP" "$@"; }

snap() {
  local unit=$1
  printf '%s|%s|%s|%s|%s' \
    "$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)" \
    "$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)" \
    "$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)" \
    "$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)" \
    "$(systemctl show "$unit" -p Result --value 2>/dev/null || true)"
}

HEAD=$(git_owner rev-parse HEAD)
BRANCH=$(git_owner branch --show-current)
WORKTREE=$(git_owner status --porcelain=v1 --untracked-files=all)
[[ "$HEAD" == "$EXPECTED_HEAD" && "$BRANCH" == main && -z "$WORKTREE" ]] || stop_now repo_baseline_changed
[[ "$(stat -c %a "$APP/src/flop_agent/observer_lobby_capture.py")" == 644 ]] || stop_now capture_mode_changed
[[ "$(stat -c %a "$APP/src/flop_agent/close1_discord_progress.py")" == 644 ]] || stop_now discord_source_mode_changed
grep -q 'def _background_poll_allowed' "$APP/src/flop_agent/close1_discord_progress.py" || stop_now pressure_gate_source_missing
grep -q 'close1_candidate_scanner' "$APP/src/flop_agent/close1_discord_progress.py" || stop_now candidate_scanner_source_missing

[[ "$(snap "$RES")" == "active|running|$RES_PID|0|success" ]] || stop_now resident_baseline_changed
[[ "$(snap "$CAP")" == "active|running|$CAP_PID|0|success" ]] || stop_now capture_baseline_changed
[[ "$(snap "$SIG")" == "active|running|$SIG_PID|0|success" ]] || stop_now signer_baseline_changed
[[ "$(snap "$DIS")" == "active|running|$DIS_PID|0|success" ]] || stop_now discord_baseline_changed

"$PY" - "$OBS" "$CORE_E" "$CORE_M" "$BRIDGE_E" "$BRIDGE_M" <<'PY' || stop_now protected_baseline_changed
import json,pathlib,sys
o=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"))
m=o.get("metrics") or {}
expected=tuple(map(int,sys.argv[2:]))
actual=(
    int(m.get("unrecoverable_core_gap_events",0) or 0),
    int(m.get("unrecoverable_core_gap_messages",0) or 0),
    int(m.get("lobby_startup_bridge_unrecoverable_events",0) or 0),
    int(m.get("lobby_startup_bridge_unrecoverable_messages",0) or 0),
)
raise SystemExit(0 if actual==expected else 1)
PY

[[ ! -e "$MARKER" && ! -e "$BLOCKED" ]] || stop_now activation_marker_already_exists

cat >"$ACTIVATOR" <<'SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

APP=/opt/technocore-safe-agent
PY=$APP/.venv/bin/python
EXPECTED_HEAD=498d332ff70cc6e5487982e27711097793a16c86
OBS=/var/lib/technocore-safe-agent/observer/observer-state.json
HB=/var/lib/technocore-safe-agent/observer/observer-heartbeat.json
SAFETY=/var/lib/technocore-safe-agent/observer-safety.json
MARKER=/var/lib/technocore-safe-agent/resident/close1-discord-runtime-activated.json
BLOCKED=/var/lib/technocore-safe-agent/resident/close1-discord-runtime-blocked.json
LOCK=/run/lock/technocore-close1-discord-activation.lock

RES=technocore-safe-agent-resident.service
CAP=technocore-safe-agent-lobby-capture.service
SIG=technocore-safe-agent-signer.service
DIS=technocore-safe-agent-discord.service

RES_PID=2462149
CAP_PID=2708820
SIG_PID=2462068
DIS_PID=2660066
CORE_E=143
CORE_M=5652707
BRIDGE_E=26
BRIDGE_M=569552

exec 9>"$LOCK"
flock -n 9 || exit 0
[[ ! -e "$MARKER" && ! -e "$BLOCKED" ]] || exit 0

block() {
  local reason=$1
  "$PY" - "$BLOCKED" "$reason" <<'PY'
import json,os,pathlib,sys,tempfile
from datetime import UTC,datetime
p=pathlib.Path(sys.argv[1]);reason=sys.argv[2]
p.parent.mkdir(parents=True,exist_ok=True)
value={"schema_version":1,"status":"blocked","reason":reason,"at":datetime.now(UTC).isoformat()}
with tempfile.NamedTemporaryFile("w",encoding="utf-8",dir=p.parent,prefix=f".{p.name}.",suffix=".tmp",delete=False) as h:
    tmp=h.name;json.dump(value,h,separators=(",",":"),sort_keys=True);h.write("\n");h.flush();os.fsync(h.fileno())
os.replace(tmp,p);os.chmod(p,0o644)
PY
  echo "CLOSE1_ACTIVATION=BLOCKED:$reason"
  exit 0
}

snap() {
  local unit=$1
  printf '%s|%s|%s|%s|%s' \
    "$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)" \
    "$(systemctl show "$unit" -p SubState --value 2>/dev/null || true)" \
    "$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)" \
    "$(systemctl show "$unit" -p NRestarts --value 2>/dev/null || true)" \
    "$(systemctl show "$unit" -p Result --value 2>/dev/null || true)"
}

OWNER=$(stat -c %U "$APP/.git" 2>/dev/null || true)
[[ -n "$OWNER" ]] || block git_owner_missing
HEAD=$(runuser -u "$OWNER" -- git -C "$APP" rev-parse HEAD 2>/dev/null || true)
BRANCH=$(runuser -u "$OWNER" -- git -C "$APP" branch --show-current 2>/dev/null || true)
DIRTY=$(runuser -u "$OWNER" -- git -C "$APP" status --porcelain=v1 --untracked-files=all 2>/dev/null || true)
[[ "$HEAD" == "$EXPECTED_HEAD" && "$BRANCH" == main && -z "$DIRTY" ]] || block repo_baseline_changed

[[ "$(snap "$RES")" == "active|running|$RES_PID|0|success" ]] || block resident_baseline_changed
[[ "$(snap "$CAP")" == "active|running|$CAP_PID|0|success" ]] || block capture_baseline_changed
[[ "$(snap "$SIG")" == "active|running|$SIG_PID|0|success" ]] || block signer_baseline_changed
[[ "$(snap "$DIS")" == "active|running|$DIS_PID|0|success" ]] || block discord_baseline_changed

mem_kb=$(awk '/^MemAvailable:/ {print $2; exit}' /proc/meminfo)
memory_psi=$(awk '/^full / {for (i=1;i<=NF;i++) if ($i ~ /^avg10=/) {split($i,a,"="); print a[2]; exit}}' /proc/pressure/memory)
io_psi=$(awk '/^full / {for (i=1;i<=NF;i++) if ($i ~ /^avg10=/) {split($i,a,"="); print a[2]; exit}}' /proc/pressure/io)
if ! awk -v m="$mem_kb" -v mp="$memory_psi" -v ip="$io_psi" 'BEGIN { exit !(m >= 262144 && mp <= 5 && ip <= 10) }'; then
  echo "CLOSE1_ACTIVATION=WAIT:pressure"
  exit 0
fi

GATE=$("$PY" - "$HB" "$SAFETY" "$CORE_E" "$CORE_M" <<'PY'
import json,pathlib,sys,time
from datetime import UTC,datetime
hb=pathlib.Path(sys.argv[1]);sf=pathlib.Path(sys.argv[2]);ce=int(sys.argv[3]);cm=int(sys.argv[4])
def load(p):
    try:
        v=json.loads(p.read_text("utf-8"));return v if isinstance(v,dict) else {}
    except Exception:return {}
def age(v):
    try:
        d=datetime.fromisoformat(str(v).replace("Z","+00:00"))
        if d.tzinfo is None:d=d.replace(tzinfo=UTC)
        return max(0.0,(datetime.now(UTC)-d.astimezone(UTC)).total_seconds())
    except Exception:return -1.0
def mem():
    for line in pathlib.Path("/proc/meminfo").read_text("utf-8").splitlines():
        if line.startswith("MemAvailable:"):return int(line.split()[1])*1024
    return -1
def psi(kind):
    for line in pathlib.Path(f"/proc/pressure/{kind}").read_text("utf-8").splitlines():
        if line.startswith("full "):
            for f in line.split()[1:]:
                if f.startswith("avg10="):return float(f.split("=",1)[1])
    return -1.0
for i in range(7):
    h=load(hb);s=load(sf)
    ok=(
        h.get("status")=="ok" and 0<=age(h.get("updated_at"))<=300
        and s.get("health")=="ok" and 0<=age(s.get("updated_at"))<=300
        and s.get("unrecoverable_core_gap_events")==ce
        and s.get("unrecoverable_core_gap_messages")==cm
        and mem()>=256*1024*1024
        and 0<=psi("memory")<=5
        and 0<=psi("io")<=10
    )
    if not ok:
        print("STOP");break
    if i!=6:time.sleep(10)
else:
    print("PASS")
PY
)
[[ "$GATE" == PASS ]] || { echo "CLOSE1_ACTIVATION=WAIT:strict_gate"; exit 0; }

[[ "$(snap "$RES")" == "active|running|$RES_PID|0|success" ]] || block resident_changed_pre_restart
[[ "$(snap "$CAP")" == "active|running|$CAP_PID|0|success" ]] || block capture_changed_pre_restart
[[ "$(snap "$SIG")" == "active|running|$SIG_PID|0|success" ]] || block signer_changed_pre_restart
[[ "$(snap "$DIS")" == "active|running|$DIS_PID|0|success" ]] || block discord_changed_pre_restart

"$PY" - "$OBS" "$CORE_E" "$CORE_M" "$BRIDGE_E" "$BRIDGE_M" <<'PY' || block protected_changed_pre_restart
import json,pathlib,sys
o=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"));m=o.get("metrics") or {};e=tuple(map(int,sys.argv[2:]))
a=(int(m.get("unrecoverable_core_gap_events",0) or 0),int(m.get("unrecoverable_core_gap_messages",0) or 0),int(m.get("lobby_startup_bridge_unrecoverable_events",0) or 0),int(m.get("lobby_startup_bridge_unrecoverable_messages",0) or 0))
raise SystemExit(0 if a==e else 1)
PY

systemctl restart "$DIS"
NEW_PID=''
for _ in $(seq 1 30); do
  S=$(snap "$DIS")
  IFS='|' read -r a sub p nr result <<<"$S"
  if [[ "$a" == active && "$sub" == running && "$p" != 0 && "$p" != "$DIS_PID" && "$nr" == 0 && "$result" == success ]]; then
    NEW_PID=$p
    break
  fi
  sleep 1
done
[[ -n "$NEW_PID" ]] || block discord_restart_not_stable
sleep 30

[[ "$(snap "$RES")" == "active|running|$RES_PID|0|success" ]] || block resident_changed_post_restart
[[ "$(snap "$CAP")" == "active|running|$CAP_PID|0|success" ]] || block capture_changed_post_restart
[[ "$(snap "$SIG")" == "active|running|$SIG_PID|0|success" ]] || block signer_changed_post_restart
[[ "$(snap "$DIS")" == "active|running|$NEW_PID|0|success" ]] || block discord_changed_post_restart

"$PY" - "$OBS" "$CORE_E" "$CORE_M" "$BRIDGE_E" "$BRIDGE_M" "$MARKER" "$NEW_PID" <<'PY' || block protected_changed_post_restart
import json,os,pathlib,sys,tempfile
from datetime import UTC,datetime
o=json.loads(pathlib.Path(sys.argv[1]).read_text("utf-8"));m=o.get("metrics") or {};e=tuple(map(int,sys.argv[2:6]))
a=(int(m.get("unrecoverable_core_gap_events",0) or 0),int(m.get("unrecoverable_core_gap_messages",0) or 0),int(m.get("lobby_startup_bridge_unrecoverable_events",0) or 0),int(m.get("lobby_startup_bridge_unrecoverable_messages",0) or 0))
if a!=e:raise SystemExit(1)
p=pathlib.Path(sys.argv[6]);pid=int(sys.argv[7]);p.parent.mkdir(parents=True,exist_ok=True)
value={"schema_version":1,"status":"activated","discord_pid":pid,"at":datetime.now(UTC).isoformat()}
with tempfile.NamedTemporaryFile("w",encoding="utf-8",dir=p.parent,prefix=f".{p.name}.",suffix=".tmp",delete=False) as h:
    tmp=h.name;json.dump(value,h,separators=(",",":"),sort_keys=True);h.write("\n");h.flush();os.fsync(h.fileno())
os.replace(tmp,p);os.chmod(p,0o644)
PY

echo "CLOSE1_ACTIVATION=PASS discord_pid=$NEW_PID"
SCRIPT
chmod 0755 "$ACTIVATOR"

cat >"$UNIT" <<'UNIT'
[Unit]
Description=Activate Close Call Discord runtime when restart gate is safe
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/technocore-close1-discord-activate-if-safe
Nice=10
IOSchedulingClass=idle
NoNewPrivileges=true
PrivateTmp=true
UNIT

cat >"$TIMER" <<'TIMER'
[Unit]
Description=Check Close Call Discord activation safety every five minutes

[Timer]
OnBootSec=30s
OnUnitActiveSec=5min
AccuracySec=15s
Unit=technocore-safe-agent-close1-discord-activation.service

[Install]
WantedBy=timers.target
TIMER

systemctl daemon-reload
systemctl enable --now technocore-safe-agent-close1-discord-activation.timer

[[ "$(systemctl is-enabled technocore-safe-agent-close1-discord-activation.timer)" == enabled ]] || stop_now timer_not_enabled
[[ "$(systemctl is-active technocore-safe-agent-close1-discord-activation.timer)" == active ]] || stop_now timer_not_active

echo "PROD560V1=PASS_AUTOWATCH_INSTALLED"
echo "SOURCE=$EXPECTED_HEAD"
echo "TIMER=active/enabled cadence=5m"
echo "ACTION=wait_for_strict_gate_then_restart_discord_once"
echo "RESIDENT_RESTART=NO CAPTURE_RESTART=NO SIGNER_RESTART=NO"
echo "DO_NOT_RERUN=YES"
