#!/usr/bin/env python3
"""R969 OFFHOST ONLY: stream real shard bytes and verify full-file reassembly.

Inputs are private; no source guest/network/write. A passing self-pinned source
census is NOT proof that it originated on OCI or belongs to one writer epoch.
All live deployment, migration and deletion authorizations remain FALSE.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    'flop_r966_shard_plan', HERE / 'verify-flop-shard-plan.py')
r966 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r966)
Stop = r966.Stop
need = r966.need
BLOCK = 1024 * 1024
MAX_PROPOSED_BYTES = 64 * 1024**3
SQLITE_MAGIC = b'SQLite format 3\x00'


def open_secure_dir(path):
    """Open EACH absolute component without following symlinks."""
    need(hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'O_DIRECTORY'),
         'SHARD_SECURE_OPEN_UNSUPPORTED_STOP')
    p = Path(path)
    need(p.is_absolute() and '..' not in p.parts,
         'SHARD_ROOT_ABSOLUTE_REQUIRED_STOP')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    current = os.open('/', flags)
    try:
        for component in p.parts[1:]:
            child = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def exact_directory(fd, names):
    """Reject foreign, symlinked and non-regular entries."""
    found = set()
    with os.scandir(fd) as entries:
        for entry in entries:
            name = entry.name
            need(name not in found and name in names,
                 'SHARD_UNLISTED_PAYLOAD_STOP')
            found.add(name)
            mode = entry.stat(follow_symlinks=False).st_mode
            need(stat.S_ISDIR(mode) if names[name] == 'directory'
                 else stat.S_ISREG(mode),
                 'SHARD_PAYLOAD_TYPE_STOP')
    need(found == set(names), 'SHARD_EXPECTED_PAYLOAD_MISSING_STOP')


def safe_file_stream(fd, filename, expected_size, expected_sha, aggregate,
                     *, is_capture=False):
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
    file_fd = os.open(filename, flags, dir_fd=fd)
    try:
        first = os.fstat(file_fd)
        need(stat.S_ISREG(first.st_mode) and first.st_nlink == 1,
             'SHARD_UNSAFE_PAYLOAD_FILE_STOP')
        need(first.st_size == expected_size, 'SHARD_PAYLOAD_LENGTH_STOP')
        digest = hashlib.sha256()
        seen = 0
        magic = b''
        while seen < expected_size:
            chunk = os.read(file_fd, min(BLOCK, expected_size - seen))
            need(bool(chunk), 'SHARD_PAYLOAD_PREMATURE_EOF_STOP')
            if is_capture and len(magic) < len(SQLITE_MAGIC):
                magic += chunk[:len(SQLITE_MAGIC) - len(magic)]
            digest.update(chunk)
            if aggregate is not None:
                aggregate.update(chunk)
            seen += len(chunk)
        need(not os.read(file_fd, 1), 'SHARD_PAYLOAD_EXTRA_BYTES_STOP')
        after = os.fstat(file_fd)
        need((first.st_dev, first.st_ino, first.st_size, first.st_mtime_ns,
              first.st_ctime_ns, first.st_mode, first.st_nlink) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
              after.st_ctime_ns, after.st_mode, after.st_nlink),
             'SHARD_PAYLOAD_CHANGED_DURING_READ_STOP')
        need(digest.hexdigest() == expected_sha,
             'SHARD_PAYLOAD_SHA256_MISMATCH_STOP')
        if is_capture:
            need(magic == SQLITE_MAGIC,
                 'SHARD_CAPTURE_NOT_SQLITE_IMAGE_STOP')
        return seen
    finally:
        os.close(file_fd)


def check_bytes(census, plan, root):
    # This is deliberately a strict extension of existing R966 geometry.
    geometry = r966.check(census, plan)
    source = r966.census_index(census)
    by_source = {}
    capture = []
    directory_names = {}
    total_proposed = 0
    for shard in plan['shards']:
        sid = shard['id']
        expected = {}
        for index, part in enumerate(shard['parts']):
            name = f'part-{index:03d}.bin'
            expected[name] = 'file'
            entry = (sid, name, part)
            total_proposed += part['size']
            if part['kind'] == 'capture_image':
                capture.append(entry)
            else:
                by_source.setdefault(part['path'], []).append(entry)
        directory_names[sid] = expected
    need(total_proposed <= MAX_PROPOSED_BYTES,
         'SHARD_REAL_BYTES_TOTAL_BOUND_STOP')
    root_fd = open_secure_dir(root)
    shard_fds = {}
    try:
        exact_directory(root_fd, {sid: 'directory' for sid in directory_names})
        for sid, expected in directory_names.items():
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            fd = os.open(sid, flags, dir_fd=root_fd)
            shard_fds[sid] = fd
            exact_directory(fd, expected)
        reconstructed = 0
        chunks = 0
        for path, segments in sorted(by_source.items()):
            sha = hashlib.sha256()
            size = 0
            # Existing geometry already rejects gaps and overlaps.
            for sid, filename, part in sorted(segments, key=lambda e: e[2]['offset']):
                size += safe_file_stream(
                    shard_fds[sid], filename, part['size'], part['sha256'], sha)
                chunks += 1
            expected_size, expected_sha = source[path]
            need(size == expected_size and sha.hexdigest() == expected_sha,
                 'SHARD_ORIGINAL_REASSEMBLED_SHA256_MISMATCH_STOP')
            reconstructed += 1
        images = 0
        for sid, filename, part in capture:
            safe_file_stream(shard_fds[sid], filename, part['size'],
                             part['sha256'], None, is_capture=True)
            images += 1
        # Recheck exact directory membership after the read, still no
        # global immutability/source provenance claim.
        for sid, expected in directory_names.items():
            exact_directory(shard_fds[sid], expected)
        exact_directory(root_fd, {sid: 'directory' for sid in directory_names})
        need(chunks == geometry['state_chunks'] and
             reconstructed == geometry['source_files'] and images == 2,
             'SHARD_REASSEMBLY_ACCOUNTING_STOP')
        return {'files': reconstructed, 'chunks': chunks,
                'capture_images': images, 'read_bytes': total_proposed}
    finally:
        for fd in shard_fds.values():
            os.close(fd)
        os.close(root_fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-census', required=True)
    parser.add_argument('--source-census-sha256', required=True)
    parser.add_argument('--shard-plan', required=True)
    parser.add_argument('--shard-plan-sha256', required=True)
    parser.add_argument('--archive-root', required=True)
    a = parser.parse_args()
    need(not Path('/opt/technocore-safe-agent').exists() and
         not Path('/opt/tradebot-k137').exists(),
         'SHARD_LIVE_HOST_REFUSED_STOP')
    source = r966.safe_json(a.source_census, a.source_census_sha256,
                            r966.MAX_CENSUS_BYTES)
    plan = r966.safe_json(a.shard_plan, a.shard_plan_sha256,
                          r966.MAX_PLAN_BYTES)
    result = check_bytes(source, plan, a.archive_root)
    print('FLOP_OFFHOST_SHARD_REAL_BYTES_REASSEMBLY_MATCH_TO_SUPPLIED_CENSUS')
    for key, value in result.items():
        print(f'FLOP_OFFHOST_SHARD_{key.upper()}={value}')
    print('FLOP_ORACLE_SOURCE_CENSUS_AUTHENTICITY_NOT_PROVEN')
    print('FLOP_ORIGINAL_ALL_WRITER_EPOCH_NOT_PROVEN')
    print('FLOP_SQLITE_ONLINE_BACKUP_COHERENCE_NOT_PROVEN')
    print('FLOP_ARCHIVE_ENCRYPTION_AND_EXTERNAL_CUSTODY_NOT_PROVEN')
    print('FLOP_INDEPENDENT_APPLICATION_RESTORE_NOT_PROVEN')
    print('FLOP_ORIGINAL_SIGNER_DID_AND_NONCE_REPLAY_NOT_PROVEN')
    print('FLOP_K137_ISOLATION_AND_CUTOVER_NOT_PROVEN')
    print('FLOP_OCI_DELETION_NEVER_AUTHORIZED_BY_THIS_TOOL')


if __name__ == '__main__':
    try:
        main()
    except (Stop, OSError, ValueError, TypeError, UnicodeError) as error:
        print('FLOP_OFFHOST_SHARD_BYTES_STOP=' +
              (str(error) if isinstance(error, Stop) else type(error).__name__))
        sys.exit(42)
