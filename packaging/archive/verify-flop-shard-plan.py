#!/usr/bin/env python3
"""R966 OFFHOST ONLY: geometry of whole-source lossless shard proposals.

An authenticated original Oracle census, actual chunk bytes, SQLite continuity,
original DID and encrypted independent restore are NOT established here.
This *never* authorizes archive deletion, a cutover or OCI retirement.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

SOURCE_SHA = 'ec4bc4892d40cdd2a03e102faa44d72c89e01b99'
HEX = re.compile(r'[0-9a-f]{64}\Z')
ID = re.compile(r'[a-z][a-z0-9-]{0,23}\Z')
COMPONENT = re.compile(r'[A-Za-z0-9_.-]+\Z')
CENSUS_KIND = 'flop-original-source-census-v1'
PLAN_KIND = 'flop-full-source-shard-plan-v1'
DBS = frozenset(('observer/lobby-capture.sqlite3',
                 'observer/lobby-capture-service.sqlite3'))
SIDECARS = frozenset(db + s for db in DBS for s in ('-wal', '-shm', '-journal'))
IMAGES = frozenset(('capture/lobby-capture.sqlite3',
                    'capture/lobby-capture-service.sqlite3'))
REQUIRED = frozenset((
    'verified-did.json', 'nonces.json', 'activities.jsonl',
    'observer-safety.json', 'observer/observer-state.json',
    'observer/resident-state.json', 'observer/observer-config.json',
    'observer/resident-config.json', 'observer/observer-heartbeat.json',
    'signer/oracle-signer-receipts.json', 'signer/signer-health.json',
    'signer/upstream-health.json', 'autopilot/autopilot-outbox.json',
    'autopilot/autopilot-audit.jsonl',
))
MAX_CENSUS_BYTES = 12 * 1024**2
MAX_PLAN_BYTES = 12 * 1024**2
MAX_SOURCE_FILES = 25000
MAX_SHARDS = 64
MAX_PARTS_PER_SHARD = 512
MAX_SHARD_BYTES = 6 * 1024**3
MAX_PART_BYTES = 3 * 1024**3
MAX_SINGLE_SOURCE_BYTES = 2**48
EMPTY_SHA = hashlib.sha256(b'').hexdigest()

class Stop(Exception):
    pass

def need(ok, code):
    if not ok:
        raise Stop(code)

def safe_path(path):
    need(isinstance(path, str) and 0 < len(path) <= 238,
         'SHARD_PATH_INVALID_STOP')
    bits = path.split('/')
    need(len(bits) <= 8 and all(COMPONENT.fullmatch(b) and
         b not in ('.', '..') for b in bits), 'SHARD_PATH_INVALID_STOP')
    return path

def digest(d):
    need(isinstance(d, str) and HEX.fullmatch(d) is not None,
         'SHARD_DIGEST_INVALID_STOP')
    return d

def safe_json(path, pin, bound):
    digest(pin)
    p = Path(path)
    need(p.is_file() and not p.is_symlink(), 'SHARD_INPUT_NOT_REGULAR_STOP')
    with p.open('rb') as f:
        raw = f.read(bound + 1)
    need(0 < len(raw) <= bound, 'SHARD_DOCUMENT_BOUND_STOP')
    need(hashlib.sha256(raw).hexdigest() == pin,
         'SHARD_INDEPENDENT_PIN_MISMATCH_STOP')
    # No ambiguous duplicate JSON keys; input digest does not prove provenance.
    def unique(pairs):
        out = {}
        for key, value in pairs:
            need(key not in out, 'SHARD_DUPLICATE_JSON_KEY_STOP')
            out[key] = value
        return out
    doc = json.loads(raw, object_pairs_hook=unique)
    need(isinstance(doc, dict), 'SHARD_DOCUMENT_SCHEMA_STOP')
    return doc

def census_index(doc):
    need(isinstance(doc, dict) and set(doc) == {
        'kind', 'source_commit', 'scope', 'walk_complete', 'unknown_roots',
        'symlinks', 'special', 'hardlinks', 'file_count', 'logical_bytes', 'files'
    } and doc['kind'] == CENSUS_KIND and doc['scope'] == 'FLOP_STATE_DIR'
         and doc['source_commit'] == SOURCE_SHA, 'SHARD_CENSUS_SCHEMA_STOP')
    need(doc['walk_complete'] is True and doc['unknown_roots'] == []
         and all(type(doc[k]) is int and doc[k] == 0
                 for k in ('symlinks', 'special', 'hardlinks')),
         'SHARD_CENSUS_INCOMPLETE_STOP')
    rows = doc['files']
    need(isinstance(rows, list) and len(rows) <= MAX_SOURCE_FILES,
         'SHARD_CENSUS_RECORD_BOUND_STOP')
    seen = {}
    total = 0
    for row in rows:
        need(isinstance(row, dict) and set(row) == {'path', 'type', 'size', 'sha256'},
             'SHARD_SOURCE_ROW_SCHEMA_STOP')
        path = safe_path(row['path'])
        size = row['size']
        need(path not in seen and row['type'] == 'regular' and
             type(size) is int and 0 <= size <= MAX_SINGLE_SOURCE_BYTES,
             'SHARD_SOURCE_DUPLICATE_OR_TYPE_STOP')
        hashvalue = row['sha256']
        if hashvalue is not None:
            digest(hashvalue)
        seen[path] = (size, hashvalue)
        total += size
    need(type(doc['file_count']) is int and doc['file_count'] == len(seen)
         and type(doc['logical_bytes']) is int and doc['logical_bytes'] == total,
         'SHARD_SOURCE_SUMMARY_STOP')
    need(REQUIRED | DBS <= set(seen), 'SHARD_ORIGINAL_REQUIRED_MISSING_STOP')
    return seen

def check(census_doc, plan_doc):
    source = census_index(census_doc)
    need(isinstance(plan_doc, dict) and set(plan_doc) == {
        'kind', 'schema', 'source_commit', 'shards'
    } and plan_doc['kind'] == PLAN_KIND and type(plan_doc['schema']) is int
         and plan_doc['schema'] == 1 and plan_doc['source_commit'] == SOURCE_SHA,
         'SHARD_PLAN_SCHEMA_STOP')
    shards = plan_doc['shards']
    need(isinstance(shards, list) and 1 <= len(shards) <= MAX_SHARDS,
         'SHARD_COUNT_LIMIT_STOP')
    spans = {}
    images = set()
    shard_ids = set()
    chunks = 0
    total_bytes = 0
    for shard in shards:
        need(isinstance(shard, dict) and set(shard) == {'id', 'parts'},
             'SHARD_ITEM_SCHEMA_STOP')
        ident = shard['id']
        need(isinstance(ident, str) and ID.fullmatch(ident) and
             ident not in shard_ids, 'SHARD_ID_INVALID_STOP')
        shard_ids.add(ident)
        parts = shard['parts']
        need(isinstance(parts, list) and 1 <= len(parts) <= MAX_PARTS_PER_SHARD,
             'SHARD_PART_COUNT_STOP')
        group_bytes = 0
        for part in parts:
            need(isinstance(part, dict) and
                 set(part) in ({'kind', 'path', 'offset', 'size', 'sha256'},
                               {'kind', 'path', 'size', 'sha256'}),
                 'SHARD_PART_SCHEMA_STOP')
            kind, path = part['kind'], safe_path(part['path'])
            size = part['size']
            need(type(size) is int and 0 <= size <= MAX_PART_BYTES,
                 'SHARD_PART_SIZE_STOP')
            dg = digest(part['sha256'])
            group_bytes += size
            need(group_bytes <= MAX_SHARD_BYTES, 'SHARD_BYTES_LIMIT_STOP')
            if kind == 'capture_image':
                need('offset' not in part and path in IMAGES and path not in images,
                     'SHARD_CAPTURE_IMAGE_STOP')
                images.add(path)
                # Images are synthetic references, not checked SQLite bytes.
                need(size > 0, 'SHARD_CAPTURE_IMAGE_EMPTY_STOP')
            elif kind == 'state_chunk':
                need('offset' in part and path in source and
                     path not in DBS | SIDECARS, 'SHARD_STATE_ORIGIN_STOP')
                offset = part['offset']
                origin_size, origin_sha = source[path]
                need(origin_sha is not None, 'SHARD_SOURCE_DIGEST_MISSING_STOP')
                need(type(offset) is int and 0 <= offset <= origin_size and
                     size <= origin_size - offset, 'SHARD_CHUNK_RANGE_STOP')
                need((size > 0) if origin_size > 0 else
                     (offset == 0 and size == 0 and dg == EMPTY_SHA),
                     'SHARD_CHUNK_ZERO_STOP')
                spans.setdefault(path, []).append((offset, size))
                chunks += 1
            else:
                raise Stop('SHARD_UNKNOWN_KIND_STOP')
        total_bytes += group_bytes
    need(images == IMAGES, 'SHARD_TWO_CAPTURE_IMAGES_MISSING_STOP')
    required = set(source) - DBS - SIDECARS
    need(set(spans) == required, 'SHARD_ORIGINAL_SOURCE_OMITTED_STOP')
    for path, entries in spans.items():
        expected = 0
        for offset, size in sorted(entries):
            need(offset == expected, 'SHARD_GAP_OVERLAP_OR_REPEAT_STOP')
            expected += size
        need(expected == source[path][0], 'SHARD_SOURCE_TRUNCATED_STOP')
    return {'shards': len(shards), 'state_chunks': chunks,
            'source_files': len(required), 'total_plan_bytes': total_bytes}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-census', required=True)
    parser.add_argument('--source-census-sha256', required=True)
    parser.add_argument('--shard-plan', required=True)
    parser.add_argument('--shard-plan-sha256', required=True)
    a = parser.parse_args()
    need(not Path('/opt/technocore-safe-agent').exists() and
         not Path('/opt/tradebot-k137').exists(), 'SHARD_LIVE_HOST_REFUSED_STOP')
    s = safe_json(a.source_census, a.source_census_sha256, MAX_CENSUS_BYTES)
    p = safe_json(a.shard_plan, a.shard_plan_sha256, MAX_PLAN_BYTES)
    summary = check(s, p)
    print('FLOP_SHARD_PLAN_GEOMETRY_MATCH_ONLY')
    for name, val in summary.items():
        print('FLOP_SHARD_PLAN_' + name.upper() + '=' + str(val))
    print('FLOP_SOURCE_HOST_AUTHENTICITY_NOT_PROVEN')
    print('FLOP_SOURCE_FULL_WALK_NOT_INDEPENDENTLY_PROVEN')
    print('FLOP_ORIGINAL_ALL_WRITER_EPOCH_NOT_PROVEN')
    print('FLOP_SOURCE_AND_CHUNK_BYTES_NOT_REASSEMBLED_OR_PROVEN')
    print('FLOP_SQLITE_ONLINE_BACKUP_COHERENCE_NOT_PROVEN')
    print('FLOP_ENCRYPTION_AND_OFFHOST_RESTORE_NOT_PROVEN')
    print('FLOP_OCI_DELETION_NEVER_AUTHORIZED_BY_THIS_TOOL')

if __name__ == '__main__':
    try:
        main()
    except (Stop, OSError, TypeError, ValueError, UnicodeError) as error:
        print('FLOP_SHARD_PLAN_STOP=' +
              (str(error) if isinstance(error, Stop) else type(error).__name__))
        sys.exit(42)
