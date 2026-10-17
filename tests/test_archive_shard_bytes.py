"""R969 synthetic-only real byte reconstruction tests; never access OCI or keys."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'packaging/archive/verify-flop-shard-bytes.py'


def load():
    spec = importlib.util.spec_from_file_location('r969', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture(m, tmp_path):
    r = m.r966
    source = {}
    for path in sorted(r.REQUIRED | r.DBS):
        source[path] = b'original-persistent-content:' + path.encode()
    source['observer/.temp-do-not-omit'] = b'sensitive-temporary-original' * 2
    source['airdrop-radar/events.jsonl'] = b'{\n"event":1\n}\n'
    old = {
        'kind': r.CENSUS_KIND, 'source_commit': r.SOURCE_SHA,
        'scope': 'FLOP_STATE_DIR', 'walk_complete': True,
        'unknown_roots': [], 'symlinks': 0, 'special': 0, 'hardlinks': 0,
        'file_count': len(source),
        'logical_bytes': sum(len(v) for v in source.values()),
        'files': [{'path': path, 'type': 'regular', 'size': len(data),
                   'sha256': hashlib.sha256(data).hexdigest()}
                  for path, data in sorted(source.items())],
    }
    images = {name: b'SQLite format 3\x00' + bytes(100) for name in r.IMAGES}
    grouped = [{'id': 'segment-a', 'parts': []}, {'id': 'segment-b', 'parts': []}]
    content = {}
    index = 0
    for path, data in sorted(source.items()):
        if path in r.DBS:
            continue
        cut = len(data)//2 if path == 'observer/.temp-do-not-omit' else len(data)
        pieces = [data] if cut == len(data) else [data[:cut], data[cut:]]
        offset = 0
        for piece in pieces:
            shard = grouped[index % 2]
            part = {'kind': 'state_chunk', 'path': path, 'offset': offset,
                    'size': len(piece), 'sha256': hashlib.sha256(piece).hexdigest()}
            number = len(shard['parts'])
            shard['parts'].append(part)
            content[(shard['id'], f'part-{number:03d}.bin')] = piece
            offset += len(piece)
            index += 1
    for path, value in sorted(images.items()):
        shard = grouped[index % 2]
        number = len(shard['parts'])
        shard['parts'].append({'kind': 'capture_image', 'path': path,
                               'size': len(value),
                               'sha256': hashlib.sha256(value).hexdigest()})
        content[(shard['id'], f'part-{number:03d}.bin')] = value
        index += 1
    plan = {'kind': r.PLAN_KIND, 'schema': 1,
            'source_commit': r.SOURCE_SHA, 'shards': grouped}
    root = tmp_path / 'private-offhost'
    root.mkdir()
    for shard in grouped:
        (root/shard['id']).mkdir()
    for (sid, name), value in content.items():
        (root/sid/name).write_bytes(value)
    return old, plan, root


def test_r969_actual_bytes_reassembled_across_shards(tmp_path):
    m = load()
    source, plan, root = fixture(m, tmp_path)
    result = m.check_bytes(source, plan, root)
    assert result['files'] == len(source['files']) - 2
    assert result['capture_images'] == 2
    assert result['chunks'] > result['files']
    assert result['read_bytes'] > 0


def test_r969_changed_chunk_rejected_even_when_length_same(tmp_path):
    m = load()
    source, plan, root = fixture(m, tmp_path)
    file = root/'segment-a'/'part-000.bin'
    buf = bytearray(file.read_bytes())
    buf[-1] ^= 1
    file.write_bytes(buf)
    with pytest.raises(m.Stop, match='SHARD_PAYLOAD_SHA256_MISMATCH_STOP'):
        m.check_bytes(source, plan, root)


def test_r969_self_consistent_forged_chunk_still_fails_original_full_hash(tmp_path):
    m = load()
    source, plan, root = fixture(m, tmp_path)
    file = root/'segment-a'/'part-000.bin'
    buf = bytearray(file.read_bytes())
    buf[-1] ^= 1
    file.write_bytes(buf)
    name = file.name
    part = plan['shards'][0]['parts'][int(name[5:8])]
    part['sha256'] = hashlib.sha256(buf).hexdigest()
    with pytest.raises(m.Stop, match='SHARD_ORIGINAL_REASSEMBLED_SHA256_MISMATCH_STOP'):
        m.check_bytes(source, plan, root)


def test_r969_missing_chunk_rejected(tmp_path):
    m = load()
    source, plan, root = fixture(m, tmp_path)
    (root/'segment-a'/'part-000.bin').unlink()
    with pytest.raises(m.Stop, match='SHARD_EXPECTED_PAYLOAD_MISSING_STOP'):
        m.check_bytes(source, plan, root)


def test_r969_unlisted_file_rejected(tmp_path):
    m = load()
    source, plan, root = fixture(m, tmp_path)
    (root/'segment-a'/'hidden.bin').write_bytes(b'suspect')
    with pytest.raises(m.Stop, match='SHARD_UNLISTED_PAYLOAD_STOP'):
        m.check_bytes(source, plan, root)


def test_r969_unlisted_directory_rejected(tmp_path):
    m = load()
    source, plan, root = fixture(m, tmp_path)
    (root/'extra').mkdir()
    with pytest.raises(m.Stop, match='SHARD_UNLISTED_PAYLOAD_STOP'):
        m.check_bytes(source, plan, root)


def test_r969_chunk_symlink_refused_without_following(tmp_path):
    m = load()
    source, plan, root = fixture(m, tmp_path)
    path = root/'segment-a'/'part-000.bin'
    path.unlink()
    path.symlink_to(tmp_path/'no-such-target')
    with pytest.raises(m.Stop, match='SHARD_PAYLOAD_TYPE_STOP'):
        m.check_bytes(source, plan, root)


def test_r969_shard_dir_symlink_refused_without_following(tmp_path):
    m = load()
    source, plan, root = fixture(m, tmp_path)
    path = root/'segment-a'
    for f in path.iterdir():
        f.unlink()
    path.rmdir()
    path.symlink_to(tmp_path/'no-such-target', target_is_directory=True)
    with pytest.raises(m.Stop, match='SHARD_PAYLOAD_TYPE_STOP'):
        m.check_bytes(source, plan, root)


def test_r969_sqlite_header_checked_but_not_coherence(tmp_path):
    m = load()
    source, plan, root = fixture(m, tmp_path)
    sid, file_index = None, None
    for shard in plan['shards']:
        for i, part in enumerate(shard['parts']):
            if part['kind'] == 'capture_image':
                sid, file_index = shard['id'], i
                break
        if sid:
            break
    path = root/sid/f'part-{file_index:03d}.bin'
    data = b'not a SQLite DB!' + bytes(100)
    path.write_bytes(data)
    part = plan['shards'][0 if sid == 'segment-a' else 1]['parts'][file_index]
    part['size'] = len(data)
    part['sha256'] = hashlib.sha256(data).hexdigest()
    with pytest.raises(m.Stop, match='SHARD_CAPTURE_NOT_SQLITE_IMAGE_STOP'):
        m.check_bytes(source, plan, root)


def test_r969_untrusted_origin_census_cannot_prove_real_oracle(tmp_path):
    m = load()
    source, plan, root = fixture(m, tmp_path)
    # A matching synthetic pair proves only supplied data, not the guest.
    assert m.check_bytes(source, plan, root)['capture_images'] == 2


def test_r969_external_pin_cli_only_returns_redacted_aggregates(tmp_path):
    m = load()
    source, plan, root = fixture(m, tmp_path)
    doc1 = tmp_path/'private-census.json'
    doc2 = tmp_path/'private-plan.json'
    doc1.write_text(json.dumps(source))
    doc2.write_text(json.dumps(plan))
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    cmd = [sys.executable, '-I', str(SCRIPT),
           '--source-census', str(doc1), '--source-census-sha256', digest(doc1),
           '--shard-plan', str(doc2), '--shard-plan-sha256', digest(doc2),
           '--archive-root', str(root)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'REAL_BYTES_REASSEMBLY_MATCH_TO_SUPPLIED_CENSUS' in result.stdout
    assert 'ORIGINAL_ALL_WRITER_EPOCH_NOT_PROVEN' in result.stdout
    assert 'OCI_DELETION_NEVER_AUTHORIZED' in result.stdout
    assert '.temp-do-not-omit' not in result.stdout
    cmd[cmd.index('--shard-plan-sha256')+1] = '0'*64
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    assert result.returncode == 42
    assert 'SHARD_INDEPENDENT_PIN_MISMATCH_STOP' in result.stdout
    assert '.temp-do-not-omit' not in result.stdout


def test_r969_chunk_truncation_rejected(tmp_path):
    m = load()
    source, plan, root = fixture(m, tmp_path)
    file = root/'segment-a'/'part-000.bin'
    file.write_bytes(file.read_bytes()[:-1])
    with pytest.raises(m.Stop, match='SHARD_PAYLOAD_LENGTH_STOP'):
        m.check_bytes(source, plan, root)
