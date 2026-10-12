#!/usr/bin/env python3
"""R860: OCI Cloud Shell existing identity read-only root-bucket survey. Paste only."""
import configparser
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

REGION = "ap-tokyo-1"
CONFIG = Path("/etc/oci/config")
TOKEN = Path("/etc/oci/delegation_token")
TENANCY_RE = re.compile(r"^ocid1\.tenancy\.oc1\.[A-Za-z0-9._-]{8,}$")
ALLOWED = {
    ("os", "ns", "get"),
    ("os", "bucket", "list"),
    ("os", "bucket", "get"),
}
MAX_BUCKETS = 3

class Stop(Exception):
    pass

def require(ok, reason):
    if not ok:
        raise Stop(reason)

def load_tenancy(config, profile):
    require(config.is_file() and not config.is_symlink(), "CLOUD_SHELL_CONFIG_ABSENT")
    parser = configparser.ConfigParser(interpolation=None)
    with config.open(encoding="utf-8") as handle:
        parser.read_file(handle)
    require(profile in parser and "tenancy" in parser[profile],
            "CLOUD_SHELL_PROFILE_ABSENT")
    value = parser[profile]["tenancy"].strip()
    require(TENANCY_RE.fullmatch(value) is not None, "ROOT_COMPARTMENT_INVALID")
    return value

def admission():
    require(not sys.argv[1:] and os.geteuid() != 0, "ARGUMENTS_OR_ROOT_STOP")
    require(not Path("/opt/technocore-safe-agent").exists() and
            not Path("/opt/tradebot-k137").exists(), "PROTECTED_VM_STOP")
    require(os.environ.get("OCI_CLI_AUTH") == "instance_obo_user",
            "CLOUD_SHELL_AUTH_ABSENT")
    require(os.environ.get("OCI_CLI_CONFIG_FILE") == str(CONFIG),
            "CLOUD_SHELL_CONFIG_ENV_INVALID")
    require(os.environ.get("OCI_CLI_PROFILE") == REGION,
            "CLOUD_SHELL_REGION_PROFILE_UNCONFIRMED")
    require(TOKEN.is_file() and not TOKEN.is_symlink(),
            "CLOUD_SHELL_DELEGATION_TOKEN_ABSENT")
    require(shutil.which("oci") is not None, "OCI_CLI_ABSENT")
    return load_tenancy(CONFIG, REGION)

def cli(*args):
    require(tuple(args[:3]) in ALLOWED, "UNAPPROVED_METHOD_STOP")
    env = {k: v for k, v in os.environ.items()
           if k not in ("OCI_CLI_DEBUG", "OCI_CLI_AUTO_PROMPT")}
    proc = subprocess.run(
        ["oci", *args, "--region", REGION, "--max-retries", "0",
         "--output", "json"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        check=False, timeout=22, env=env,
    )
    require(proc.returncode == 0 and len(proc.stdout) <= 131072,
            "OCI_READ_ONLY_API_UNAVAILABLE")
    result = json.loads(proc.stdout)
    require(isinstance(result, dict), "OCI_RESPONSE_NOT_OBJECT")
    return result

def run():
    tenancy = admission()
    namespace = cli("os", "ns", "get").get("data")
    require(isinstance(namespace, str) and 0 < len(namespace) < 256,
            "NAMESPACE_READ_FAILED")
    listing = cli("os", "bucket", "list", "--compartment-id", tenancy,
                  "--namespace", namespace, "--limit", str(MAX_BUCKETS + 1))
    buckets = listing.get("data")
    require(isinstance(buckets, list) and len(buckets) <= MAX_BUCKETS + 1,
            "ROOT_BUCKET_LIST_INVALID")
    print("FLOP_R860_ROOT_BUCKETS_OBSERVED=" + str(len(buckets)), flush=True)
    if len(buckets) > MAX_BUCKETS:
        print("FLOP_R860_ROOT_LIST_PARTIAL", flush=True)
    else:
        sizes = []
        all_private = True
        for bucket in buckets:
            name = bucket.get("name") if isinstance(bucket, dict) else None
            require(isinstance(name, str) and 0 < len(name) <= 256,
                    "BUCKET_SUMMARY_INVALID")
            size_info = cli("os", "bucket", "get",
                            "--namespace", namespace, "--bucket-name", name,
                            "--fields", "approximateSize").get("data")
            privacy_info = cli("os", "bucket", "get",
                               "--namespace", namespace, "--bucket-name", name).get("data")
            require(isinstance(size_info, dict) and isinstance(privacy_info, dict),
                    "BUCKET_METADATA_UNAVAILABLE")
            size = size_info.get("approximate-size")
            sizes.append(size if type(size) is int and size >= 0 else None)
            if privacy_info.get("public-access-type") != "NoPublicAccess":
                all_private = False
        if all(item is not None for item in sizes):
            print("FLOP_R860_ROOT_APPROX_BYTES=" + str(sum(sizes)), flush=True)
        else:
            print("FLOP_R860_ROOT_BYTES_UNCONFIRMED", flush=True)
        print("FLOP_R860_ROOT_PRIVACY=" +
              ("NO_BUCKETS" if not buckets else
               "ALL_PRIVATE" if all_private else "NOT_ALL_CONFIRMED_PRIVATE"), flush=True)
    print("FLOP_R860_ROOT_ONLY_NOT_TENANCY_TOTAL", flush=True)
    print("FLOP_R860_STORAGE_QUOTA_FREE_TIER_BILLING_UNCONFIRMED", flush=True)
    print("FLOP_R860_NO_CLOUD_MUTATION", flush=True)
    print("FLOP_R860_READ_ONLY_SURVEY_PASS", flush=True)

if __name__ == "__main__":
    try:
        run()
    except (Stop, OSError, ValueError, KeyError, UnicodeError, configparser.Error,
            json.JSONDecodeError, subprocess.TimeoutExpired) as err:
        reason = str(err) if isinstance(err, Stop) else type(err).__name__
        print("FLOP_R860_SURVEY_STOP=" + reason, flush=True)
        sys.exit(42)
