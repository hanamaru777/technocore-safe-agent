"""R1106 retained TechnoCore upstream export witness, GET-only and nonauthorizing.

Official TechnoCore export sends byte-exact retained JSONL with
X-Room-Generation. A retained ring is not full historical POST finality.
Explicit --room required for a public room. Never GET a write-path.
"""
from __future__ import annotations
import hashlib
import json
import re
import ssl
import sys
import urllib.request
import urllib.error

ROOM = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}\Z")
MAX_BYTES = 12 * 1024 * 1024
MAX_LINES = 100000
HOST = "https://technocore.chat"
class Stop(ValueError):
    pass

def need(x, code):
    if not x: raise Stop(code)

def _pairs(pairs):
    value = {}
    for k,v in pairs:
        need(k not in value, "DUPLICATE_JSON_KEY")
        value[k] = v
    return value

def parse_export(raw, generation):
    """Inspect source bytes only; never output record content, DID, nonce or room."""
    need(type(raw) is bytes and len(raw) <= MAX_BYTES, "EXPORT_BOUND_STOP")
    need(type(generation) is str and re.fullmatch(r"[0-9]{1,19}", generation), "GENERATION_STOP")
    need(int(generation) >= 1, "GENERATION_STOP")
    sha = hashlib.sha256(raw).hexdigest()
    if not raw:
        return {"result": "EMPTY_UNVERIFIED", "count": 0, "contiguous": False,
                "first_seq": None, "last_seq": None, "bytes_sha256": sha}
    need(raw.endswith(b"\n"), "TORN_EXPORT_STOP")
    lines = raw.splitlines()
    need(0 < len(lines) <= MAX_LINES, "EXPORT_BOUND_STOP")
    previous = None
    first = None
    for line in lines:
        need(0 < len(line) <= 131072, "RECORD_SIZE_STOP")
        try:
            item = json.loads(line, object_pairs_hook=_pairs,
                 parse_constant=lambda _: (_ for _ in ()).throw(Stop("JSON_SCHEMA_STOP")))
        except (ValueError, UnicodeError, RecursionError) as error:
            raise Stop("JSON_SCHEMA_STOP") from None
        need(type(item) is dict and type(item.get("seq")) is int and
             1 <= item["seq"] <= 2**63 - 1, "SEQUENCE_STOP")
        seq = item["seq"]
        need(previous is None or seq == previous + 1, "RETAINED_GAP_STOP")
        if first is None: first = seq
        previous = seq
    return {"result": "RETAINED_RING_ONLY", "count": len(lines),
            "contiguous": True, "first_seq": first, "last_seq": previous,
            "bytes_sha256": sha}

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None

def fetch_public_room(room):
    need(type(room) is str and ROOM.fullmatch(room), "ROOM_STOP")
    need(not room.startswith("p-"), "PRIVATE_ROOM_STOP")
    url = HOST + "/r/" + room + "/export"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
             urllib.request.HTTPSHandler(context=ssl.create_default_context()),
             _NoRedirect())
    request = urllib.request.Request(url, method="GET",
                 headers={"Accept": "application/x-ndjson",
                          "User-Agent": "FLOP-R1106-readonly/1"})
    try:
        with opener.open(request, timeout=15) as response:
            need(response.status == 200, "UPSTREAM_HTTP_STOP")
            generation = response.headers.get("X-Room-Generation")
            need(type(generation) is str, "GENERATION_STOP")
            body = response.read(MAX_BYTES + 1)
        return parse_export(body, generation)
    except (OSError, urllib.error.URLError):
        raise Stop("UPSTREAM_FETCH_STOP") from None

def audit_public_room(room=None, *, fetcher=None):
    result={"phase":"R1106","operation":"PUBLIC_READ_ONLY",
            "evidence":"RETAINED_RING_NOT_FULL_HISTORY",
            "public_room_export":"NOT_VERIFIED","export_count":None,
            "export_sha256":None,"generation":"NOT_ATTESTED",
            "post_finality":"NOT_PROVEN","five_routes":"NOT_PROVEN",
            "source_archive":"NOT_AUTHORIZED","cutover":"NO_GO",
            "oci_retirement":"STRICT_NO_GO"}
    if room is None:
        result["operation"]="OFFLINE"
        return result
    try:
        if fetcher is None: report=fetch_public_room(room)
        else:
            need(type(room) is str and ROOM.fullmatch(room) and
                 not room.startswith("p-"), "ROOM_STOP")
            raw,generation=fetcher(room)
            report=parse_export(raw,generation)
        result["public_room_export"]=report["result"]
        result["export_count"]=report["count"]
        result["export_sha256"]=report["bytes_sha256"]
    except (Stop, OSError, ValueError, TypeError, RecursionError):
        result["public_room_export"]="REJECTED_OR_UNAVAILABLE"
    return result

def main(argv=None):
    args=sys.argv[1:] if argv is None else argv
    if not args: report=audit_public_room()
    elif len(args)==2 and args[0]=="--live-public-room":
        report=audit_public_room(args[1])
    else:
        print('{"phase":"R1106","result":"INVALID_ARGUMENTS","cutover":"NO_GO"}')
        return 2
    print(json.dumps(report,sort_keys=True))
    return 0 if report["public_room_export"] != "REJECTED_OR_UNAVAILABLE" else 2

if __name__=="__main__":
    raise SystemExit(main())
