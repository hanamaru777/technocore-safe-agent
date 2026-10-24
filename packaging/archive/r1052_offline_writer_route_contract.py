#!/usr/bin/env python3
"""R1052 pure in-memory ORIGINAL-OCI writer route coverage contract.

It does NOT read any filesystem, run systemctl, access OCI/AWS, use tokens,
touch mutable state, or authorize service stops/cutovers. The input MUST be
an independently acquired offline source snapshot. The output is never a
production fence or an OCI retirement proof, even when all template pins match.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping

ORIGINAL_SOURCE_HEAD = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99"

# Git blob identities from ORIGINAL SOURCE HEAD, packaging/oracle/*.service/timer.
# These are SOURCE templates, NOT a claim about installed/active systemd state.
ORIGINAL_TEMPLATE_GIT_BLOBS = {
    "airdrop-monitor.service": "5c0575c39b73c73f9df05626f43a095dba0b01c0",
    "airdrop-monitor.timer": "3224743f49b34df34acf044d42322c072f2ed641",
    "airdrop-notifier.service": "5c842d0f5fd413609fe9a09c2e79d89138bf38a5",
    "airdrop-notifier.timer": "bdb91e3c14748646dbe4f21a62acfb22dd5af991",
    "discord.service": "085b1a105e18b1f48ebcd62f74202cb16341f821",
    "lobby-capture.service": "bdf71c805d179bda50dde0df4db7930f5308099d",
    "resident.service": "67c173c328f13fc0f8ed2ec24ecec4190df35a53",
    "technocore-safe-agent-close1-approved-trade.service": "03d6ac863051637aa9b644eb55d6204421d8f081",
    "technocore-safe-agent-close1-auto-resident.service": "cd17a98f32775cdc7088943a370417df3ab3b44b",
    "technocore-safe-agent-close1-batch-trade.service": "cb2b86dcfcf23379fe29f7d629aa18bda4c25261",
    "technocore-safe-agent-close1-standalone-watch.service": "859fe465180ac26e81d09b0f0e824e151232ed21",
    "technocore-safe-agent-metadata-block.service": "4053ee9b13d82327e06c7abfdb6f8d5f41d94653",
    "technocore-safe-agent-precontest-supervisor.service": "335d0b6aaa8a49e2d8ca3bd01bed9132eb92d335",
    "technocore-safe-agent-precontest-supervisor.timer": "faeac611812f5918e22d81cb8d0a7be8a996062e",
    "technocore-safe-agent-signer.service": "d78015ce4af0d53e8f8a386e7cc4b3a0755736f6",
    "technocore-safe-agent-tclk-accept@.service": "852cd1267374bfe0d632eb901f61f73f1a9c375c",
    "technocore-safe-agent-tclk-lock-watcher.service": "13b33e269ef269b77fa8aff2ac5e09b917870c16",
    "technocore-safe-agent-tclk-lock-watcher.timer": "4cc0d709ba62b715d92d86aab9c611ed547db8b9",
    "technocore-safe-agent-tclk-preparer.service": "4e294030846e6b2cd4c7d55ac665a2073eb05293",
    "technocore-safe-agent-tclk-preparer.timer": "b014c6bbcc3df5a96bae46887a8bb7095eb5354f",
    "technocore-safe-agent-tclk-reveal-preparer.service": "ca92e84099db0ecbc6d49082ea9a6155032c5637",
    "technocore-safe-agent-tclk-reveal-preparer.timer": "df6d29fc3f860f629475e44603cfe0e4a9b360fd",
    "technocore-safe-agent-tclk-reveal@.service": "c188b89177be04982c39290f0777fdddb84cd27b",
    "technocore-safe-agent-tclk-stager.service": "6a6c452a38d7aeeacd4adb90a949ae5a74cbb6cf",
    "technocore-safe-agent-tclk-stager.timer": "0b4508bd172b830e6191aa3dedae82cc030dfd6c",
    "technocore-safe-agent-tclk-work-watcher.service": "addc9e9205038008313ee170db28580bc18bb8d2",
    "technocore-safe-agent-tclk-work-watcher.timer": "10a8cf52ea288395bc5a3decab86f94aa56499af",
}

# Explicit original-OCI sign+POST authority entry points found by R1051.
# Expected modules checked against pinned unit template ExecStart, not inferred
# from names. Manual service invocations and dynamically instantiated @ units
# remain possible: source pinning does not prove runtime admission is blocked.
SIGN_POST_ROUTES = {
    "technocore-safe-agent-signer.service": "flop_agent.oracle_signer",
    "technocore-safe-agent-tclk-accept@.service": "flop_agent.tclk_pilot_accept",
    "technocore-safe-agent-tclk-reveal@.service": "flop_agent.tclk_pilot_reveal_publish",
    "technocore-safe-agent-close1-approved-trade.service": "flop_agent.close1_approved_trade",
    "technocore-safe-agent-close1-batch-trade.service": "flop_agent.close1_batch_trade",
}

# Previously discovered only on running original OCI; NOT Git source templates.
UNEXPECTED_INSTALLED_NAMES_FROM_R1034 = frozenset({
    "technocore-safe-agent-close1-discord-activation.service",
    "technocore-safe-agent-close1-discord-activation.timer",
    "technocore-safe-agent-close1-standalone-watch.timer",
    "technocore-safe-agent-postreboot-check.service",
})

ORIGINAL_MISSING_INSTALLED_FROM_R1034 = frozenset({
    "technocore-safe-agent-close1-auto-resident.service",
})

ORIGINAL_STILL_UNPROVEN = (
    "full_dynamic_tclk_instance_census",
    "all_transient_manual_systemd_authority",
    "all_cron_entries_and_effective_interpreters",
    "complete_process_fd_cgroup_and_relaunch_inventory",
    "unknown_installed_services_execstart_effect",
    "all_signer_close1_tclk_external_post_acceptance",
    "all_nonce_ledger_receipt_inflight_reconciliation",
    "resident_independent_capture_all_writer_quiescence",
    "single_writer_epoch_for_both_sqlite_and_full_state",
    "authenticated_original_oci_offhost_restore",
    "aws_same_did_secret_custody_and_resource_isolation",
)

MAX_SOURCE_BYTES = 8192
BLOB_ID = re.compile(r"[a-f0-9]{40}\Z")
MODULE = re.compile(r"^ExecStart=/opt/technocore-safe-agent/\.venv/bin/python -m ([a-zA-Z_][\w.]*)(?: %i)?$", re.M)


class CoverageStop(Exception):
    """Fixed-code rejection without emitting content, path or credentials."""


def git_blob_sha1(content: bytes) -> str:
    """Compute Git blob identity, rather than hashing ordinary SHA-1 bytes."""
    if not isinstance(content, bytes) or len(content) > MAX_SOURCE_BYTES:
        raise CoverageStop("SOURCE_TYPE_OR_SIZE_STOP")
    return hashlib.sha1(
        b"blob " + str(len(content)).encode("ascii") + b"\0" + content
    ).hexdigest()


def audit_offline_original_templates(sources: Mapping[str, bytes]) -> dict:
    """Validate exactly 27 original-HEAD unit source bytes, NEVER runtime state.

    Callers do not control the baked-in pin map; no production shell, cloud,
    filesystem or network capability is reachable from this module.
    """
    if not isinstance(sources, Mapping):
        raise CoverageStop("SOURCE_MAPPING_STOP")
    keys = set(sources)
    if keys != set(ORIGINAL_TEMPLATE_GIT_BLOBS):
        raise CoverageStop("TEMPLATE_EXACT_SET_STOP")
    if len(keys) != 27 or sum(n.endswith(".timer") for n in keys) != 8:
        raise CoverageStop("TEMPLATE_COUNTS_STOP")
    if not all(isinstance(name, str) and isinstance(ORIGINAL_TEMPLATE_GIT_BLOBS[name], str)
               and BLOB_ID.fullmatch(ORIGINAL_TEMPLATE_GIT_BLOBS[name]) for name in keys):
        raise CoverageStop("TEMPLATE_PIN_SCHEMA_STOP")

    for name in sorted(keys):
        content = sources[name]
        if git_blob_sha1(content) != ORIGINAL_TEMPLATE_GIT_BLOBS[name]:
            raise CoverageStop("TEMPLATE_PIN_MISMATCH_STOP")
    if set(SIGN_POST_ROUTES) - keys:
        raise CoverageStop("SIGN_ROUTE_ABSENT_STOP")
    if len(SIGN_POST_ROUTES) != 5:
        raise CoverageStop("SIGN_ROUTE_COUNT_STOP")
    if set(UNEXPECTED_INSTALLED_NAMES_FROM_R1034) & keys:
        raise CoverageStop("UNEXPECTED_UNIT_MISCLASSIFIED_STOP")
    if set(ORIGINAL_MISSING_INSTALLED_FROM_R1034) - keys:
        raise CoverageStop("MISSING_INSTALLED_TEMPLATE_STOP")

    for name, module in SIGN_POST_ROUTES.items():
        try:
            decoded = sources[name].decode("utf-8", "strict")
        except UnicodeError:
            raise CoverageStop("SIGN_ROUTE_ENCODING_STOP") from None
        found = MODULE.findall(decoded)
        if len(found) != 1 or found[0] != module:
            raise CoverageStop("SIGN_ROUTE_MODULE_DRIFT_STOP")

    # Even exact template pins cannot prove ANY source runtime state.
    return {
        "schema_version": 1,
        "original_source_head": ORIGINAL_SOURCE_HEAD,
        "template_sources_pinned": len(keys),
        "service_templates": len(keys) - 8,
        "timer_templates": 8,
        "sign_and_post_entrypoint_templates": len(SIGN_POST_ROUTES),
        "dynamic_template_instance_enumeration": "NOT_PROVEN",
        "original_installed_unit_census_now": "NOT_PROVEN",
        "r1034_unexpected_installed": len(UNEXPECTED_INSTALLED_NAMES_FROM_R1034),
        "r1034_known_source_missing_installed": len(ORIGINAL_MISSING_INSTALLED_FROM_R1034),
        "all_unproven_categories": list(ORIGINAL_STILL_UNPROVEN),
        "all_writers_fenced": "NO",
        "signer_inflight_post_resolved": "NO",
        "full_state_common_epoch": "NOT_PROVEN",
        "aws_signer_did_custody": "NOT_PROVEN",
        "oci_retirement": "STRICT_NO_GO",
        "no_files_or_services_touched": "YES",
    }
