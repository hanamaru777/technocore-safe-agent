#!/usr/bin/env python3
"""OCI Cloud Shell only. Paste via python3 stdin; no GitHub fetch, cloud writes or secrets output."""
import configparser
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys

REGION = "ap-tokyo-1"
CONFIG = Path("/etc/oci/config")
TENANCY_RE = re.compile(r"^ocid1\.tenancy\.oc1\.[A-Za-z0-9._-]{8,}$")
ALLOWED = {("os", "ns", "get"), ("os", "bucket", "list"), ("os", "bucket", "get")}
MAX_BUCKETS = 3

class Stop(Exception):
    pass

def require(ok, reason):
    if not ok:
        raise Stop(reason)

def tenancy_from_config(path, profile):
    require(path.is_file() and not path.is_symlink(), "CLOUDSHELL_CONFIG_MISSING")
    parser = configparser.ConfigParser(interpolation=None)
    with path.open(encoding="utf-8") as file:
        parser.read_file(file)
    require(profile in parser and "tenancy" in parser[profile], "TENANCY_PROFILE_UNAVAILABLE")
    value = parser[profile]["tenancy"].strip()
    require(TENANCY_RE.fullmatch(value) is not None, "TENANCY_INVALID")
    return value

def cloud_shell_guard():
    require(not sys.argv[1:] and os.geteuid() != 0, "NO_ARGS_NO_ROOT_REQUIRED")
    require("cloudshell" in socket.gethostname().lower(), "WRONG_HOST_CLOUDSHELL_ONLY")
    require(os.environ.get("OCI_CLI_AUTH") == "instance_obo_user", "CLOUDSHELL_AUTH_ABSENT")
    require(os.environ.get("OCI_CLI_CONFIG_FILE") == str(CONFIG), "CLOUDSHELL_CONFIG_PATH_INVALID")
    require(os.environ.get("OCI_CLI_PROFILE") == REGION, "CLOUDSHELL_PROFILE_REGION_INVALID")
    require(not Path("/opt/technocore-safe-agent").exists() and
            not Path("/opt/tradebot-k137").exists(), "PROTECTED_VM_STOP")
    require(shutil.which("oci") is not None, "OCI_CLI_NOT_AVAILABLE")
    return tenancy_from_config(CONFIG, REGION)

def cli(*args):
    require(tuple(args[:3]) in ALLOWED, "NON_READ_ONLY_METHOD_STOP")
    env = {k: v for k, v in os.environ.items()
           if k not in ("OCI_CLI_DEBUG", "OCI_CLI_AUTO_PROMPT")}
    p = subprocess.run(["oci", *args, "--region", REGION, "--max-retries", "0",
                        "--output", "json"],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                       timeout=22, check=False, env=env)
    require(p.returncode == 0 and len(p.stdout) <= 131072, "OCI_READ_UNAVAILABLE")
    obj = json.loads(p.stdout)
    require(isinstance(obj, dict), "OCI_RESPONSE_INVALID")
    return obj

def run():
    tenancy = cloud_shell_guard()
    ns = cli("os", "ns", "get").get("data")
    require(isinstance(ns, str) and 0 < len(ns) < 256, "NAMESPACE_UNAVAILABLE")
    result = cli("os", "bucket", "list", "--compartment-id", tenancy,
                 "--namespace", ns, "--limit", str(MAX_BUCKETS + 1))
    buckets = result.get("data")
    require(isinstance(buckets, list) and len(buckets) <= MAX_BUCKETS + 1,
            "BUCKET_LIST_INVALID")
    print("FLOP_STORAGE_ROOT_BUCKETS_OBSERVED=" + str(len(buckets)), flush=True)
    if len(buckets) > MAX_BUCKETS:
        print("FLOP_STORAGE_ROOT_LIST_PARTIAL", flush=True)
    else:
        sizes = []
        all_private = True
        for row in buckets:
            name = row.get("name") if isinstance(row, dict) else None
            require(isinstance(name, str) and 0 < len(name) <= 256,
                    "BUCKET_SUMMARY_INVALID")
            size_data = cli("os", "bucket", "get", "--namespace", ns,
                            "--bucket-name", name, "--fields", "approximateSize").get("data")
            privacy_data = cli("os", "bucket", "get", "--namespace", ns,
                               "--bucket-name", name).get("data")
            require(isinstance(size_data, dict) and isinstance(privacy_data, dict),
                    "BUCKET_DETAILS_UNAVAILABLE")
            size = size_data.get("approximate-size")
            sizes.append(size if type(size) is int and size >= 0 else None)
            all_private &= privacy_data.get("public-access-type") == "NoPublicAccess"
        if all(value is not None for value in sizes):
            print("FLOP_STORAGE_ROOT_APPROX_BYTES=" + str(sum(sizes)), flush=True)
        else:
            print("FLOP_STORAGE_ROOT_SIZE_UNCONFIRMED", flush=True)
        print("FLOP_STORAGE_ROOT_PRIVACY=" +
              ("NO_BUCKETS" if not buckets else "ALL_PRIVATE" if all_private else
               "NOT_ALL_CONFIRMED_PRIVATE"), flush=True)
    print("FLOP_STORAGE_ROOT_ONLY_NOT_TENANCY_TOTAL", flush=True)
    print("FLOP_STORAGE_QUOTA_CREDITS_BILLING_UNCONFIRMED", flush=True)
    print("FLOP_STORAGE_NO_CREATE_UPLOAD_DELETE_OR_IAM_ACTION", flush=True)
    print("FLOP_STORAGE_DIRECT_CLOUDSHELL_READONLY_PASS", flush=True)

if __name__ == "__main__":
    try:
        run()
    except (Stop, OSError, ValueError, KeyError, UnicodeError, configparser.Error,
            json.JSONDecodeError, subprocess.TimeoutExpired) as err:
        reason = str(err) if isinstance(err, Stop) else type(err).__name__
        print("FLOP_STORAGE_DIRECT_CLOUDSHELL_STOP=" + reason, flush=True)
        sys.exit(42)
