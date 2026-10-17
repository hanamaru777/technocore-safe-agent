"""R966 synthetic-only full-source shard plan coverage; no Oracle or archives."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPT = (Path(__file__).resolve().parents[1] /
          'packaging/archive/verify-flop-shard-plan.py')


def module():
    spec = importlib.util.spec_from_file_location('r966', SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def fixtures(m, *, extra=0):
    source = {path: (11, hashlib.sha256(path.encode()).hexdigest())
              for path in m.REQUIRED | m.DBS}
    source['observer/.temporary-looking.999'] = (5, 'b' * 64)
    for i in range(extra):
        name = f'observer/temporary-{i:05d}.log'
        source[name] = (1, hashlib.sha256(name.encode()).hexdigest())
    census = {
        'kind': m.CENSUS_KIND, 'source_commit': m.SOURCE_SHA,
        'scope': 'FLOP_STATE_DIR', 'walk_complete': True,
        'unknown_roots': [], 'symlinks': 0, 'special': 0, 'hardlinks': 0,
        'file_count': len(source),
        'logical_bytes': sum(val[0] for val in source.values()),
        'files': [{'path': path, 'type': 'regular', 'size': size, 'sha256': sha}
                  for path, (size, sha) in sorted(source.items())],
    }
    parts = [
        {'kind': 'state_chunk', 'path': path, 'offset': 0, 'size': size, 'sha256': sha}
        for path, (size, sha) in sorted(source.items()) if path not in m.DBS
    ]
    parts += [{'kind': 'capture_image', 'path': path, 'size': 32, 'sha256': 'a' * 64}
              for path in sorted(m.IMAGES)]
    shards = [{'id': f'part-{n}', 'parts': parts[i:i + m.MAX_PARTS_PER_SHARD]}
              for n, i in enumerate(range(0, len(parts), m.MAX_PARTS_PER_SHARD))]
    plan = {'kind': m.PLAN_KIND, 'schema': 1,
            'source_commit': m.SOURCE_SHA, 'shards': shards}
    return census, plan


def parts(p):
    return [part for shard in p['shards'] for part in shard['parts']]


def test_r966_3017_file_synthetic_shards_do_not_lose_source():
    m = module()
    census, plan = fixtures(m, extra=3000)
    result = m.check(census, plan)
    assert census['file_count'] >= 3017
    assert len(plan['shards']) >= 6
    assert result['source_files'] == census['file_count'] - 2
    assert result['state_chunks'] == result['source_files']
    assert result['shards'] == len(plan['shards'])


def test_r966_large_single_file_can_only_be_represented_as_bounded_chunks():
    m = module()
    census, plan = fixtures(m)
    path = 'observer/.temporary-looking.999'
    original_sha = 'e' * 64
    new_size = m.MAX_PART_BYTES + 7
    for row in census['files']:
        if row['path'] == path:
            row['size'] = new_size
            row['sha256'] = original_sha
    census['logical_bytes'] += new_size - 5
    chunk = next(item for item in parts(plan) if item.get('path') == path)
    chunk['size'] = m.MAX_PART_BYTES
    chunk['sha256'] = 'c' * 64
    # A single shard containing a 3GiB chunk exceeds the shard limit only if
    # all its other segments add >3GiB; these are all small.
    plan['shards'].append({'id': 'second', 'parts': [
        {'kind': 'state_chunk', 'path': path, 'offset': m.MAX_PART_BYTES,
         'size': 7, 'sha256': 'd' * 64}]})
    assert m.check(census, plan)['state_chunks'] == len(census['files']) - 1
    plan['shards'][-1]['parts'][0]['offset'] -= 1
    with pytest.raises(m.Stop, match='SHARD_GAP_OVERLAP_OR_REPEAT_STOP'):
        m.check(census, plan)


@pytest.mark.parametrize('bad,reason', [
    ('omit_tmp', 'SHARD_ORIGINAL_SOURCE_OMITTED_STOP'),
    ('duplicate_chunk', 'SHARD_GAP_OVERLAP_OR_REPEAT_STOP'),
    ('phantom_chunk', 'SHARD_STATE_ORIGIN_STOP'),
    ('wrong_offset', 'SHARD_SOURCE_TRUNCATED_STOP'),
    ('duplicate_capture', 'SHARD_CAPTURE_IMAGE_STOP'),
    ('missing_capture', 'SHARD_TWO_CAPTURE_IMAGES_MISSING_STOP'),
    ('symlink', 'SHARD_CENSUS_INCOMPLETE_STOP'),
    ('unknown_root', 'SHARD_CENSUS_INCOMPLETE_STOP'),
    ('unknown_source_digest', 'SHARD_SOURCE_DIGEST_MISSING_STOP'),
    ('sqlite_sidecar', 'SHARD_STATE_ORIGIN_STOP'),
    ('oversize_chunk', 'SHARD_PART_SIZE_STOP'),
    ('duplicate_shard', 'SHARD_ID_INVALID_STOP'),
    ('path_traversal', 'SHARD_PATH_INVALID_STOP'),
])
def test_r966_fail_closed(bad, reason):
    m = module()
    source, plan = fixtures(m)
    target = next(part for part in parts(plan)
                  if part.get('path') == 'observer/.temporary-looking.999')
    if bad == 'omit_tmp':
        plan['shards'][0]['parts'].remove(target)
    elif bad == 'duplicate_chunk':
        plan['shards'][0]['parts'].append(copy.deepcopy(target))
    elif bad == 'phantom_chunk':
        plan['shards'][0]['parts'].append({**target, 'path': 'unknown/path'})
    elif bad == 'wrong_offset':
        target['size'] -= 1
    elif bad == 'duplicate_capture':
        plan['shards'][0]['parts'].append(copy.deepcopy(next(p for p in parts(plan)
                         if p['kind'] == 'capture_image')))
    elif bad == 'missing_capture':
        plan['shards'][0]['parts'].remove(next(p for p in parts(plan)
                           if p['kind'] == 'capture_image'))
    elif bad == 'symlink':
        source['symlinks'] = 1
    elif bad == 'unknown_root':
        source['unknown_roots'] = ['private']
    elif bad == 'unknown_source_digest':
        next(r for r in source['files'] if r['path'] == target['path'])['sha256'] = None
    elif bad == 'sqlite_sidecar':
        target['path'] = 'observer/lobby-capture.sqlite3-wal'
    elif bad == 'oversize_chunk':
        target['size'] = m.MAX_PART_BYTES + 1
    elif bad == 'duplicate_shard':
        plan['shards'].append(copy.deepcopy(plan['shards'][0]))
    elif bad == 'path_traversal':
        target['path'] = '../private'
    with pytest.raises(m.Stop, match=reason):
        m.check(source, plan)


def test_r966_external_pin_and_no_source_path_disclosure(tmp_path):
    m = module()
    source, plan = fixtures(m)
    paths = (tmp_path/'source.json', tmp_path/'parts.json')
    for path, value in zip(paths, (source, plan)):
        path.write_text(json.dumps(value), encoding='utf-8')
    d = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    args = [sys.executable, '-I', str(SCRIPT), '--source-census', str(paths[0]),
            '--source-census-sha256', d(paths[0]), '--shard-plan', str(paths[1]),
            '--shard-plan-sha256', d(paths[1])]
    result = subprocess.run(args, text=True, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'FLOP_SHARD_PLAN_GEOMETRY_MATCH_ONLY' in result.stdout
    assert 'SOURCE_AND_CHUNK_BYTES_NOT_REASSEMBLED_OR_PROVEN' in result.stdout
    assert 'OCI_DELETION_NEVER_AUTHORIZED' in result.stdout
    assert '.temporary-looking' not in result.stdout
    args[6] = '0' * 64
    fail = subprocess.run(args, text=True, capture_output=True, timeout=15)
    assert fail.returncode == 42
    assert 'SHARD_INDEPENDENT_PIN_MISMATCH_STOP' in fail.stdout
    assert '.temporary-looking' not in fail.stdout


def test_r966_json_duplicate_keys_fail_before_check(tmp_path):
    m = module()
    path = tmp_path/'input.json'
    path.write_text('{"kind":"a","kind":"b"}', encoding='utf-8')
    with pytest.raises(m.Stop, match='SHARD_DUPLICATE_JSON_KEY_STOP'):
        m.safe_json(path, hashlib.sha256(path.read_bytes()).hexdigest(), 1000)
