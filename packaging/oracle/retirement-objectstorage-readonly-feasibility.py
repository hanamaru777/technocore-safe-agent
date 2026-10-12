#!/usr/bin/env python3
"""OCI Cloud Shell ONLY: bounded, read-only Object Storage feasibility check.

No writes, bucket/object operations, IAM changes, cloud billable provisioning,
secrets, SDK/auth plugins installed or credentials printed. Root compartment
visibility does NOT establish tenancy-wide free-capacity or billing state.
"""
import configparser
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

REGION = "ap-tokyo-1"
MAX_ROOT_BUCKETS = 3
CLI_TIMEOUT = 22
TENANCY = re.compile(r"^ocid1\.tenancy\.oc1\.[A-Za-z0-9._-]{8,}$")

class Stop(Exception):
    pass

def check(ok, reason):
    if not ok:
        raise Stop(reason)

def tenancy_id():
    value = os.environ.get("OCI_CLI_TENANCY", "").strip()
    if value:
        check(TENANCY.fullmatch(value), "TENANCY_ENV_INVALID")
        return value
    profile = os.environ.get("OCI_CLI_PROFILE", "DEFAULT")
    cfg = configparser.ConfigParser(interpolation=None)
    config_path = Path.home() / ".oci" / "config"
    check(config_path.exists() and config_path.is_file() and
          not config_path.is_symlink(), "CLOUDSHELL_CLI_PROFILE_ABSENT")
    cfg.read(config_path)
    check(profile in cfg and "tenancy" in cfg[profile],
          "TENANCY_PROFILE_ABSENT")
    value = cfg[profile]["tenancy"].strip()
    check(TENANCY.fullmatch(value), "TENANCY_PROFILE_INVALID")
    return value

def cli(*parts):
    allowed = (
        ("os", "ns", "get"),
        ("os", "bucket", "list"),
        ("os", "bucket", "get"),
        ("limits", "value", "list"),
    )
    check(tuple(parts[:3]) in allowed or
          tuple(parts[:3]) == ("limits", "value", "list"),
          "UNAPPROVED_CLI_METHOD")
    argv = ["oci", *parts, "--region", REGION, "--output", "json",
            "--max-retries", "0"]
    p = subprocess.run(
        argv, capture_output=True, text=True, timeout=CLI_TIMEOUT,
        check=False, env={
            k:v for k,v in os.environ.items()
            if k not in ("OCI_CLI_DEBUG", "OCI_CLI_AUTO_PROMPT")
        }
    )
    check(p.returncode == 0, "READ_ONLY_API_UNAVAILABLE")
    check(len(p.stdout) <= 131072, "API_RESPONSE_TOO_LARGE")
    response = json.loads(p.stdout)
    check(isinstance(response, dict), "API_RESPONSE_INVALID")
    return response

def run():
    check(not sys.argv[1:], "UNEXPECTED_ARGS")
    # Prevent running through Flop OCI systemd or the protected K137 instance.
    check(not Path("/opt/technocore-safe-agent").exists() and
          not Path("/opt/tradebot-k137").exists(),
          "WRONG_HOST_USE_OCI_CLOUD_SHELL")
    check(shutil.which("oci") is not None, "OCI_CLI_NOT_FOUND")
    tenancy = tenancy_id()
    # Only namespace access permission, never report value.
    ns = cli("os", "ns", "get")
    check(isinstance(ns.get("data"), str) and len(ns["data"]) < 256,
          "NAMESPACE_ACCESS_UNAVAILABLE")
    print("FLOP_OFFVM_OCI_OBJECTSTORAGE_NAMESPACE_READ_PASS", flush=True)
    listing = cli("os", "bucket", "list", "--compartment-id", tenancy,
                  "--limit", str(MAX_ROOT_BUCKETS + 1))
    buckets = listing.get("data")
    check(isinstance(buckets, list) and
          len(buckets) <= MAX_ROOT_BUCKETS + 1, "ROOT_BUCKETS_RESPONSE_INVALID")
    print("FLOP_OFFVM_ROOT_BUCKET_COUNT_OBSERVED=" +
          str(len(buckets)), flush=True)
    if len(buckets) > MAX_ROOT_BUCKETS:
        print("FLOP_OFFVM_ROOT_BUCKET_REVIEW_PARTIAL", flush=True)
    else:
        bytes_seen = 0
        complete = True
        private = True
        for row in buckets:
            name = row.get("name") if isinstance(row, dict) else None
            check(isinstance(name,str) and 0 < len(name) <= 256,
                  "BUCKET_NAME_INVALID")
            detail = cli("os", "bucket", "get", "--bucket-name", name,
                         "--fields", "approximateSize")
            info = detail.get("data")
            check(isinstance(info,dict), "BUCKET_DETAIL_INVALID")
            value = info.get("approximate-size")
            if type(value) is int and value >= 0:
                bytes_seen += value
            else:
                complete = False
            # --fields approximateSize often omits visibility. Never assert
            # bucket privacy from an unset value.
            if info.get("public-access-type") != "NoPublicAccess":
                private = False
        print("FLOP_OFFVM_ROOT_APPROX_SIZE_KNOWN=" +
              str(complete).lower(), flush=True)
        if complete:
            print("FLOP_OFFVM_ROOT_APPROX_BYTES=" +
                  str(bytes_seen), flush=True)
        print("FLOP_OFFVM_ROOT_PRIVATE_STATUS=" +
              ("VERIFIED" if private else "UNCONFIRMED"), flush=True)
    # Resource limits differ from Always Free inclusion and can be inaccessible.
    try:
        limits = cli("limits", "value", "list",
                     "--compartment-id", tenancy,
                     "--service-name", "object-storage", "--limit", "20")
        items = limits.get("data")
        check(isinstance(items, list), "LIMIT_RESPONSE_INVALID")
        print("FLOP_OFFVM_STORAGE_LIMIT_QUERY_ACCESSIBLE", flush=True)
    except (Stop, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired):
        print("FLOP_OFFVM_STORAGE_LIMIT_QUERY_UNCONFIRMED", flush=True)
    print("FLOP_OFFVM_ROOT_COMPARTMENT_ONLY_NOT_ALL_TENANCY", flush=True)
    print("FLOP_OFFVM_FREE_TIER_CREDIT_BILLING_UNCONFIRMED", flush=True)
    print("FLOP_OFFVM_BUCKET_CREATE_UPLOAD_DELETE_NOT_ATTEMPTED", flush=True)
    print("FLOP_OFFVM_READ_ONLY_STORAGE_FEASIBILITY_PASS", flush=True)

if __name__ == "__main__":
    try:
        run()
    except (Stop, OSError, ValueError, json.JSONDecodeError,
            configparser.Error, subprocess.TimeoutExpired) as err:
        print("FLOP_OFFVM_STORAGE_FEASIBILITY_STOP=" +
              (str(err) if isinstance(err, Stop) else type(err).__name__),
              flush=True)
        sys.exit(42)
