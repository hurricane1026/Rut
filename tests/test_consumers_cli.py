#!/usr/bin/env python3
"""Consumer administration, key generation, atomic rejection and filesystem policy."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


def run(tool, *args):
    return subprocess.run([tool, *map(str, args)], capture_output=True, timeout=10)


def private(path, value):
    path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
    path.chmod(0o600)
    return path


def changes(consumers=(), credentials=(), remove_consumers=(), remove_credentials=()):
    return dict(consumers=list(consumers), credentials=list(credentials),
                removeConsumers=list(remove_consumers), removeCredentials=list(remove_credentials))


def test_prune_credentials(tool, root):
    for args in (['prune-credentials'], ['prune-credentials', 'a', '1'],
                 ['prune-credentials', 'a', '1', 'b', 'c']):
        result = run(tool, *args)
        assert result.returncode == 2 and not result.stdout
    consumers = [dict(id='alice', enabled=True, groups=['staff', 'readers']),
                 dict(id='paused', enabled=False, groups=['staff', 'readers'])]
    def credential(name, method='bearer', **fields):
        record = dict(id=name, consumerId='alice', method=method, enabled=True,
                      secret='private-' + name)
        record.update(fields)
        return record

    raw = 'private-hashed-key'
    hashed = dict(consumerId='alice', method='header', enabled=True,
                  secretSha256=hashlib.sha256(raw.encode()).hexdigest())
    records = [credential('unbounded'),
               credential('header-raw', 'header', notBefore=0, expiresAt=0, groups=['readers']),
               credential('mtls-unbounded', 'mtls', secret='b' * 64, groups=['staff']),
               dict(hashed, id='zero-expiry', expiresAt=0, groups=[]),
               dict(hashed, id='hashed-bearer', method='bearer',
                    secretSha256=hashlib.sha256(b'private-hashed-bearer').hexdigest(), groups=['staff']),
               credential('future-basic', 'basic', secret='user:private-password',
                          notBefore=10, expiresAt=101, groups=['readers']),
               credential('boundary-mtls', 'mtls', secret='a' * 64, expiresAt=100),
               credential('retired', enabled=False, expiresAt=9223372036854775807),
               dict(hashed, id='retired-hash', enabled=False),
               credential('future-start', notBefore=200),
               credential('paused-owner', consumerId='paused', expiresAt=101),
               dict(hashed, id='expired-hash', secretSha256=hashlib.sha256(b'expired-private-key').hexdigest(),
                    expiresAt=99)]
    # Hashed credentials still obey full-snapshot ambiguity checks, including retired records.
    next(item for item in records if item['id'] == 'retired-hash')['secretSha256'] = hashlib.sha256(b'retired-private-key').hexdigest()
    snapshot = dict(version=1, consumers=consumers, credentials=records)
    source = private(root / 'prune-input.json', snapshot)
    original = source.read_bytes()
    assert run(tool, 'validate', source).returncode == 0
    counter = 0
    def prune(input_path, cutoff, expected, destination=None):
        nonlocal counter
        counter += 1
        output = destination or root / f'pruned-{counter}.json'
        before = input_path.read_bytes()
        result = run(tool, 'prune-credentials', input_path, cutoff, output)
        assert input_path.read_bytes() == before and not result.stdout
        for record in records:
            secret = record.get('secret', record.get('secretSha256')).encode()
            assert secret not in result.stderr
        if expected is None:
            assert result.returncode == 2
            if output != input_path and not output.is_symlink():
                assert not output.exists()
        else:
            assert result.returncode == 0 and not result.stderr, result
            assert json.loads(output.read_bytes()) == expected
            assert stat.S_IMODE(output.stat().st_mode) == 0o600
            assert run(tool, 'validate', output).returncode == 0
        return output

    retained = [record for record in records if record['id'] in
                ('unbounded', 'header-raw', 'mtls-unbounded', 'zero-expiry', 'hashed-bearer',
                 'future-basic', 'future-start', 'paused-owner')]
    expected = dict(snapshot, credentials=retained)
    pruned = prune(source, '100', expected)
    prune(pruned, '1', expected)  # A no-op still publishes a separate validated private snapshot.
    assert source.read_bytes() == original
    boundary = dict(snapshot, credentials=[credential('at-one', expiresAt=1),
                                          credential('after-one', expiresAt=2)])
    boundary_source = private(root / 'prune-boundary.json', boundary)
    prune(boundary_source, '1', dict(boundary, credentials=boundary['credentials'][1:]))
    prune(boundary_source, '9223372036854775807', dict(boundary, credentials=[]))
    empty_source = private(root / 'prune-empty.json', dict(snapshot, credentials=[]))
    prune(empty_source, '1', dict(snapshot, credentials=[]))
    for cutoff in ('', '0', '-0', '-1', '+1', '01', ' 1', '1 ', '1.0', '1e3',
                   '9223372036854775808', '18446744073709551615', '9' * 100):
        prune(source, cutoff, None)
    for invalid in (b'{bad', dict(snapshot, credentials=[credential('bad-owner', consumerId='missing', enabled=False)]),
                    dict(snapshot, credentials=[credential('bad-group', groups=['unknown'], enabled=False)]),
                    dict(snapshot, credentials=[credential('bad-window', notBefore=2, expiresAt=1, enabled=False)])):
        bad = private(root / f'prune-invalid-{counter}.json', invalid)
        prune(bad, '100', None)
    prune(source, '100', None, destination=source)
    existing = private(root / 'prune-existing-output', b'preserve')
    collision = run(tool, 'prune-credentials', source, '100', existing)
    assert collision.returncode == 2 and not collision.stdout and existing.read_bytes() == b'preserve'
    link = root / 'prune-output-link'
    link.symlink_to(source)
    prune(source, '100', None, destination=link)
    loose = root / 'prune-loose-directory'
    loose.mkdir(mode=0o777)
    loose.chmod(0o777)
    prune(source, '100', None, destination=loose / 'output')
    loose.chmod(0o700)
    loose_input = private(root / 'prune-loose-input', snapshot)
    loose_input.chmod(0o644)
    prune(loose_input, '100', None)
    source_link = root / 'prune-input-link'
    source_link.symlink_to(source)
    prune(source_link, '100', None)
    assert source.read_bytes() == original

    # Retiring one disabled credential frees a slot and removes its reserved ID.
    full_records = [credential('retired-slot', enabled=False)] + [credential(f'k{i}') for i in range(63)]
    full = dict(snapshot, credentials=full_records)
    full_source = private(root / 'prune-capacity.json', full)
    assert run(tool, 'validate', full_source).returncode == 0
    rotated, key = root / 'prune-full-rotate.json', root / 'prune-full-rotate.key'
    rejected = run(tool, 'rotate-key-verifier', full_source, 'k0', 'retired-slot', rotated, key)
    assert rejected.returncode == 2 and not rejected.stdout and not rotated.exists() and not key.exists()
    freed = prune(full_source, '1', dict(full, credentials=full_records[1:]))
    result = run(tool, 'rotate-key-verifier', freed, 'k0', 'retired-slot', rotated, key)
    assert result.returncode == 0 and not result.stdout and not result.stderr
    final = json.loads(rotated.read_bytes())
    assert len(final['credentials']) == 64
    replacement = next(item for item in final['credentials'] if item['id'] == 'retired-slot')
    assert replacement['secretSha256'] == hashlib.sha256(key.read_bytes()).hexdigest()

    raced = root / 'prune-race.json'
    with ThreadPoolExecutor(max_workers=6) as workers:
        results = list(workers.map(lambda _: run(tool, 'prune-credentials', source, '100', raced), range(6)))
    assert sum(result.returncode == 0 for result in results) == 1
    assert all(result.returncode in (0, 2) and not result.stdout for result in results)
    assert json.loads(raced.read_bytes()) == expected
    assert stat.S_IMODE(raced.stat().st_mode) == 0o600 and source.read_bytes() == original
    assert not list(root.glob('.rut-consumers-*'))


def test_generated_keys(tool, root):
    base = root / 'key-base.json'
    assert run(tool, 'init', base).returncode == 0
    patch = private(root / 'key-consumer.json', changes([dict(id='alice', enabled=True, groups=[])]))
    consumer_snapshot = root / 'key-consumer-snapshot.json'
    assert run(tool, 'apply', base, patch, consumer_snapshot).returncode == 0

    def generate(source, credential_id, method, destination):
        result = run(tool, 'generate-key', source, 'alice', credential_id, method, destination)
        assert result.returncode == 0 and result.stdout == b'' and result.stderr == b'', result
        snapshot = json.loads(destination.read_bytes())
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600
        credential = next(item for item in snapshot['credentials'] if item['id'] == credential_id)
        secret = credential['secret']
        assert re.fullmatch(r'[0-9a-f]{64}', secret), secret
        assert credential == dict(id=credential_id, consumerId='alice', method=method,
                                  secret=secret, enabled=True)
        assert run(tool, 'validate', destination).returncode == 0
        inspected = run(tool, 'inspect', destination)
        assert inspected.returncode == 0 and secret.encode() not in inspected.stdout + inspected.stderr
        return snapshot, secret

    first_path = root / 'generated-bearer.json'
    first, bearer = generate(consumer_snapshot, 'key-v1', 'bearer', first_path)
    second_path = root / 'generated-header.json'
    second, header = generate(consumer_snapshot, 'key-v2', 'header', second_path)
    assert bearer != header
    assert json.loads(consumer_snapshot.read_bytes())['credentials'] == []
    # Printable IDs containing JSON syntax remain valid and are quoted safely.
    quoted_consumer = 'alice"ops'
    quoted_base = root / 'quoted-base.json'
    private(quoted_base, dict(version=1, consumers=[dict(id=quoted_consumer, enabled=True, groups=[])],
                              credentials=[]))
    quoted_out = root / 'quoted-out.json'
    result = run(tool, 'generate-key', quoted_base, quoted_consumer, 'quoted-key', 'header', quoted_out)
    assert result.returncode == 0 and not result.stdout and not result.stderr
    assert json.loads(quoted_out.read_bytes())['credentials'][0]['consumerId'] == quoted_consumer

    invalid_cases = [
        ('missing', 'key-v3', 'bearer'), ('alice', 'key-v1', 'bearer'),
        ('alice', 'bad id', 'bearer'), ('alice', 'x' * 65, 'header'),
        ('bad id', 'key-v3', 'bearer'), ('x' * 65, 'key-v3', 'header'),
        ('alice', 'key-v3', 'basic'), ('alice', 'key-v3', 'mtls'),
        ('alice', 'key-v3', 'Bearer'),
    ]
    for index, (consumer_id, credential_id, method) in enumerate(invalid_cases):
        destination = root / f'invalid-generated-{index}.json'
        source = first_path if credential_id == 'key-v1' else consumer_snapshot
        result = run(tool, 'generate-key', source, consumer_id,
                     credential_id, method, destination)
        assert result.returncode == 2 and result.stdout == b''
        assert bearer.encode() not in result.stderr and not destination.exists()
    preserved = root / 'preserved-output.json'
    preserved.write_bytes(b'unchanged')
    result = run(tool, 'generate-key', consumer_snapshot, 'alice', 'fresh', 'bearer', preserved)
    assert result.returncode == 2 and not result.stdout and preserved.read_bytes() == b'unchanged'

    # Concurrent generators still publish at most one immutable destination.
    raced = root / 'generated-race.json'
    with ThreadPoolExecutor(max_workers=8) as workers:
        results = list(workers.map(
            lambda _: run(tool, 'generate-key', consumer_snapshot, 'alice',
                          'race-key', 'bearer', raced), range(8)))
    assert sum(result.returncode == 0 for result in results) == 1
    assert all(result.returncode in (0, 2) and not result.stdout for result in results)
    assert stat.S_IMODE(raced.stat().st_mode) == 0o600
    assert run(tool, 'validate', raced).returncode == 0

    disabled_base = root / 'disabled-consumer.json'
    private(disabled_base, dict(version=1,
                                consumers=[dict(id='paused', enabled=False, groups=[])],
                                credentials=[]))
    disabled_out = root / 'disabled-consumer-key.json'
    result = run(tool, 'generate-key', disabled_base, 'paused', 'staged-key', 'bearer', disabled_out)
    assert result.returncode == 0 and not result.stdout and not result.stderr
    staged = json.loads(disabled_out.read_bytes())
    assert staged['consumers'][0]['enabled'] is False
    assert staged['credentials'][0]['enabled'] is True


def test_time_window_metadata_survives_cli(tool, root):
    windowed = dict(version=1, consumers=[dict(id='alice', enabled=True, groups=['staff'])],
                    credentials=[dict(id='window', consumerId='alice', method='bearer',
                                      secret='window-secret', enabled=True,
                                      notBefore=1700000000, expiresAt=1800000000)])
    source = private(root / 'windowed-source.json', windowed)
    patch = private(root / 'windowed-changes.json', changes())
    applied = root / 'windowed-applied.json'
    result = run(tool, 'apply', source, patch, applied)
    assert result.returncode == 0, result
    assert json.loads(applied.read_bytes()) == windowed
    generated = root / 'windowed-generated.json'
    result = run(tool, 'generate-key', source, 'alice', 'windowed-new', 'bearer', generated)
    assert result.returncode == 0 and not result.stdout and not result.stderr, result
    snapshot = json.loads(generated.read_bytes())
    existing = next(item for item in snapshot['credentials'] if item['id'] == 'window')
    assert existing == windowed['credentials'][0]
    new = next(item for item in snapshot['credentials'] if item['id'] == 'windowed-new')
    assert 'notBefore' not in new and 'expiresAt' not in new
    inspected = run(tool, 'inspect', generated)
    assert inspected.returncode == 0
    redacted = json.loads(inspected.stdout)
    existing_view = next(item for item in redacted['credentials'] if item['id'] == 'window')
    assert existing_view['notBefore'] == 1700000000 and existing_view['expiresAt'] == 1800000000
    assert 'secret' not in existing_view


def test_hash_keys(tool, root):
    raw_bearer = 'a' * 64
    raw_header = 'b' * 64
    basic = 'alice:password'
    mtls = '0123456789abcdef' * 4
    existing_hash = hashlib.sha256(b'existing').hexdigest()
    snapshot = dict(
        version=1,
        consumers=[dict(id='alice', enabled=True, groups=['staff', 'readers'])],
        credentials=[
            dict(id='bearer', consumerId='alice', method='bearer', secret=raw_bearer,
                 enabled=True, notBefore=1700000000, expiresAt=1800000000, groups=['readers']),
            dict(id='header', consumerId='alice', method='header', secret=raw_header,
                 enabled=False, expiresAt=1900000000, groups=[]),
            dict(id='basic', consumerId='alice', method='basic', secret=basic, enabled=True),
            dict(id='mtls', consumerId='alice', method='mtls', secret=mtls, enabled=True),
            dict(id='already-hashed', consumerId='alice', method='header',
                 secretSha256=existing_hash, enabled=True),
        ])
    source = private(root / 'hash-source.json', snapshot)
    original = source.read_bytes()
    output = root / 'hash-output.json'
    result = run(tool, 'hash-keys', source, output)
    assert result.returncode == 0 and result.stdout == b'' and result.stderr == b'', result
    assert source.read_bytes() == original
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    hashed = json.loads(output.read_bytes())
    by_id = {item['id']: item for item in hashed['credentials']}
    assert by_id['bearer']['secretSha256'] == hashlib.sha256(raw_bearer.encode()).hexdigest()
    assert by_id['header']['secretSha256'] == hashlib.sha256(raw_header.encode()).hexdigest()
    assert 'secret' not in by_id['bearer'] and 'secret' not in by_id['header']
    assert by_id['bearer']['notBefore'] == 1700000000
    assert by_id['bearer']['expiresAt'] == 1800000000
    assert by_id['header']['enabled'] is False and by_id['header']['expiresAt'] == 1900000000
    assert by_id['bearer']['groups'] == ['readers'] and by_id['header']['groups'] == []
    assert by_id['basic']['secret'] == basic and by_id['mtls']['secret'] == mtls
    assert by_id['already-hashed']['secretSha256'] == existing_hash
    assert run(tool, 'validate', output).returncode == 0

    inspected = run(tool, 'inspect', output)
    assert inspected.returncode == 0
    for secret in [raw_bearer, raw_header, basic, mtls, existing_hash,
                   by_id['bearer']['secretSha256'], by_id['header']['secretSha256']]:
        assert secret.encode() not in inspected.stdout + inspected.stderr
    second = root / 'hash-output-again.json'
    result = run(tool, 'hash-keys', output, second)
    assert result.returncode == 0 and result.stdout == b'' and result.stderr == b''
    assert json.loads(second.read_bytes()) == hashed

    unsafe = dict(version=1, consumers=snapshot['consumers'], credentials=[
        dict(id='ok', consumerId='alice', method='bearer', secret=raw_bearer, enabled=True),
        dict(id='weak', consumerId='alice', method='header', secret='human-chosen', enabled=True),
    ])
    unsafe_path = private(root / 'hash-unsafe.json', unsafe)
    rejected_output = root / 'hash-rejected.json'
    result = run(tool, 'hash-keys', unsafe_path, rejected_output)
    assert result.returncode == 2 and result.stdout == b'' and not rejected_output.exists()
    preserved = root / 'hash-preserved.json'
    preserved.write_bytes(b'unchanged')
    result = run(tool, 'hash-keys', source, preserved)
    assert result.returncode == 2 and result.stdout == b'' and preserved.read_bytes() == b'unchanged'

    planned_digest = hashlib.sha256(b'planned').hexdigest()
    patch = private(root / 'hash-plan.json', changes(credentials=[
        dict(id='future', consumerId='alice', method='header', secretSha256=planned_digest,
             enabled=True)]))
    planned = run(tool, 'plan', source, patch)
    assert planned.returncode == 0 and planned_digest.encode() not in planned.stdout + planned.stderr


def test_generated_key_verifier(tool, root):
    credentials = [dict(id='windowed', consumerId='alice', method='bearer',
                        secret='existing-raw-key', enabled=True,
                        notBefore=1700000000, expiresAt=1800000000)]
    snapshot = dict(version=1, consumers=[dict(id='alice', enabled=True, groups=['staff'])],
                    credentials=credentials)
    source = private(root / 'paired-input.json', snapshot)
    original = source.read_bytes()

    def provision(method, credential_id):
        key_path = root / f'{credential_id}.key'
        snapshot_path = root / f'{credential_id}.snapshot.json'
        result = run(tool, 'generate-key-verifier', source, 'alice', credential_id,
                     method, snapshot_path, key_path)
        assert result.returncode == 0 and result.stdout == b'' and result.stderr == b'', result
        raw_key = key_path.read_bytes()
        assert len(raw_key) == 64 and re.fullmatch(rb'[0-9a-f]{64}', raw_key)
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(snapshot_path.stat().st_mode) == 0o600
        output = json.loads(snapshot_path.read_bytes())
        record = next(item for item in output['credentials'] if item['id'] == credential_id)
        assert record['method'] == method and record['consumerId'] == 'alice'
        assert record['secretSha256'] == hashlib.sha256(raw_key).hexdigest()
        assert 'secret' not in record
        assert raw_key not in snapshot_path.read_bytes()
        assert next(item for item in output['credentials'] if item['id'] == 'windowed') == credentials[0]
        assert run(tool, 'validate', snapshot_path).returncode == 0
        inspected = run(tool, 'inspect', snapshot_path)
        assert inspected.returncode == 0
        assert raw_key not in inspected.stdout + inspected.stderr
        assert record['secretSha256'].encode() not in inspected.stdout + inspected.stderr
        assert source.read_bytes() == original
        return snapshot_path, key_path, raw_key, record['secretSha256']

    bearer = provision('bearer', 'paired-bearer')
    header = provision('header', 'paired-header')

    # Bad arguments and output preflight fail before either output is created.
    invalid = [
        ('missing', 'new-id', 'bearer'),
        ('alice', 'windowed', 'bearer'),
        ('alice', 'new-id', 'basic'),
        ('alice', 'new-id', 'mtls'),
        ('alice', 'bad id', 'header'),
    ]
    for index, (consumer_id, credential_id, method) in enumerate(invalid):
        snapshot_path = root / f'invalid-paired-{index}.snapshot'
        key_path = root / f'invalid-paired-{index}.key'
        result = run(tool, 'generate-key-verifier', source, consumer_id, credential_id,
                     method, snapshot_path, key_path)
        assert result.returncode == 2 and not result.stdout
        assert not snapshot_path.exists() and not key_path.exists()

    alias_target = root / 'same-output'
    result = run(tool, 'generate-key-verifier', source, 'alice', 'alias-id', 'bearer',
                 alias_target, str(root) + '/./same-output')
    assert result.returncode == 2 and not result.stdout and not alias_target.exists()
    alias = root / 'directory-alias'
    alias.symlink_to(root, target_is_directory=True)
    result = run(tool, 'generate-key-verifier', source, 'alice', 'alias-id', 'bearer',
                 root / 'same-parent-name', alias / 'same-parent-name')
    assert result.returncode == 2 and not result.stdout and not (root / 'same-parent-name').exists()
    other = root / 'different-directory'
    other.mkdir()
    result = run(tool, 'generate-key-verifier', source, 'alice', 'different-dir', 'header',
                 root / 'different-snapshot', other / 'different-key')
    assert result.returncode == 2 and not result.stdout
    assert not (root / 'different-snapshot').exists() and not (other / 'different-key').exists()
    existing = root / 'existing-output'
    existing.write_bytes(b'preserve')
    absent = root / 'absent-key-output'
    result = run(tool, 'generate-key-verifier', source, 'alice', 'preflight', 'bearer',
                 existing, absent)
    assert result.returncode == 2 and not result.stdout
    assert existing.read_bytes() == b'preserve' and not absent.exists()
    existing_key = root / 'existing-key-output'
    existing_key.write_bytes(b'preserve-key')
    absent_snapshot = root / 'absent-snapshot-output'
    result = run(tool, 'generate-key-verifier', source, 'alice', 'preflight-key', 'bearer',
                 absent_snapshot, existing_key)
    assert result.returncode == 2 and not result.stdout
    assert existing_key.read_bytes() == b'preserve-key' and not absent_snapshot.exists()
    symlink_target = root / 'symlink-target'
    symlink_target.write_bytes(b'do-not-follow')
    symlink_output = root / 'symlink-output'
    symlink_output.symlink_to(symlink_target)
    symlink_peer = root / 'symlink-peer'
    result = run(tool, 'generate-key-verifier', source, 'alice', 'symlink-id', 'header',
                 symlink_peer, symlink_output)
    assert result.returncode == 2 and not result.stdout and not symlink_peer.exists()
    assert symlink_target.read_bytes() == b'do-not-follow'
    loose_dir = root / 'loose-output-dir'
    loose_dir.mkdir()
    loose_dir.chmod(0o777)
    result = run(tool, 'generate-key-verifier', source, 'alice', 'loose-id', 'bearer',
                 loose_dir / 'snapshot', loose_dir / 'key')
    loose_dir.chmod(0o700)
    assert result.returncode == 2 and not result.stdout
    assert not (loose_dir / 'snapshot').exists() and not (loose_dir / 'key').exists()

    race_snapshot = root / 'paired-race.snapshot'
    race_key = root / 'paired-race.key'
    with ThreadPoolExecutor(max_workers=6) as workers:
        results = list(workers.map(
            lambda _: run(tool, 'generate-key-verifier', source, 'alice', 'race-paired',
                          'bearer', race_snapshot, race_key), range(6)))
    assert sum(result.returncode == 0 for result in results) == 1
    assert all(result.returncode in (0, 2) and not result.stdout for result in results)
    race_raw_key = race_key.read_bytes()
    race_config = json.loads(race_snapshot.read_bytes())
    race_record = next(item for item in race_config['credentials'] if item['id'] == 'race-paired')
    assert race_record['secretSha256'] == hashlib.sha256(race_raw_key).hexdigest()
    assert len(race_raw_key) == 64 and stat.S_IMODE(race_key.stat().st_mode) == 0o600

    if sys.platform.startswith('linux'):
        # Inject publication failures without adding a production failpoint.
        shim_source = root / 'linkat-fault.c'
        shim = root / 'linkat-fault.so'
        shim_source.write_text(r'''#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
__attribute__((constructor)) static void mark_loaded(void) {
    const char *path = getenv("RUT_TEST_PRELOAD_MARKER");
    if (!path) return;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) { (void)write(fd, "1", 1); (void)close(fd); }
}
int linkat(int oldfd, const char *oldpath, int newfd, const char *newpath, int flags) {
    static int calls;
    ++calls;
    const char *fail = getenv("RUT_TEST_LINKAT_FAIL_AT");
    if (fail && atoi(fail) == calls) { errno = EIO; return -1; }
    return (int)syscall(SYS_linkat, oldfd, oldpath, newfd, newpath, flags);
}
''')
        built = subprocess.run(['cc', '-shared', '-fPIC', '-o', str(shim), str(shim_source)],
                               capture_output=True, timeout=20)
        assert built.returncode == 0, built.stderr.decode(errors='replace')
        marker = root / 'preload-capability.marker'
        probe_env = dict(os.environ, LD_PRELOAD=str(shim), RUT_TEST_PRELOAD_MARKER=str(marker))
        probe = subprocess.run([tool, '--help'], capture_output=True, timeout=10, env=probe_env)
        if probe.returncode != 0 or not marker.exists():
            reason = (f'executable did not load the preload shim (probe exit {probe.returncode})'
                      if not marker.exists() else
                      f'preload probe exited with status {probe.returncode}')
            print(f'SKIP: generated-key publication fault injection: {reason}')
        else:
            for fail_at in (1, 2):
                snapshot_path = root / f'fault-{fail_at}.snapshot'
                key_path = root / f'fault-{fail_at}.key'
                env = dict(os.environ, LD_PRELOAD=str(shim), RUT_TEST_LINKAT_FAIL_AT=str(fail_at))
                result = subprocess.run([tool, 'generate-key-verifier', str(source), 'alice',
                                         f'fault-{fail_at}', 'bearer', str(snapshot_path), str(key_path)],
                                        capture_output=True, timeout=10, env=env)
                assert result.returncode == 2 and not result.stdout
                if fail_at == 1:
                    assert not key_path.exists() and not snapshot_path.exists()
                else:
                    raw_key = key_path.read_bytes()
                    assert key_path.exists() and len(raw_key) == 64
                    assert re.fullmatch(rb'[0-9a-f]{64}', raw_key)
                    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
                    assert not snapshot_path.exists()
                    assert b'key output was published' in result.stderr
                    assert raw_key not in result.stderr and raw_key not in result.stdout
                rotated_snapshot = root / f'rotation-fault-{fail_at}.snapshot'
                rotated_key = root / f'rotation-fault-{fail_at}.key'
                before = source.read_bytes()
                result = subprocess.run([tool, 'rotate-key-verifier', str(source), 'windowed',
                                         f'rotation-fault-{fail_at}', str(rotated_snapshot), str(rotated_key)],
                                        capture_output=True, timeout=10, env=env)
                assert result.returncode == 2 and not result.stdout
                assert source.read_bytes() == before and not rotated_snapshot.exists()
                assert b'existing-raw-key' not in result.stderr
                if fail_at == 1:
                    assert not rotated_key.exists()
                else:
                    raw_key = rotated_key.read_bytes()
                    assert re.fullmatch(rb'[0-9a-f]{64}', raw_key)
                    assert stat.S_IMODE(rotated_key.stat().st_mode) == 0o600
                    assert b'key output was published' in result.stderr and raw_key not in result.stderr


def test_rotated_key_verifier(tool, root):
    owner = dict(id='rotation-owner', enabled=True, groups=['readers', 'staff'])
    original_key = 'old-private-key'
    counter = 0

    def invoke(snapshot, old='old', new='new', key_output=None, snapshot_output=None):
        nonlocal counter
        counter += 1
        source = private(root / f'rotation-{counter}.input', snapshot)
        before = source.read_bytes()
        output = snapshot_output or root / f'rotation-{counter}.snapshot'
        key = key_output or root / f'rotation-{counter}.key'
        result = run(tool, 'rotate-key-verifier', source, old, new, output, key)
        assert source.read_bytes() == before
        assert not result.stdout and original_key.encode() not in result.stderr
        return result, output, key

    for method in ('bearer', 'header'):
        for hashed in (False, True):
            for groups in (None, [], ['readers']):
                for window in ({}, dict(notBefore=0, expiresAt=0),
                               dict(notBefore=1, expiresAt=2), dict(notBefore=4102444800)):
                    source_record = dict(id='old', consumerId=owner['id'], method=method,
                                         enabled=True)
                    if hashed:
                        source_record['secretSha256'] = hashlib.sha256(original_key.encode()).hexdigest()
                    else:
                        source_record['secret'] = original_key
                    if groups is not None:
                        source_record['groups'] = groups
                    source_record.update(window)
                    snapshot = dict(version=1, consumers=[owner], credentials=[source_record])
                    result, output, key = invoke(snapshot)
                    assert result.returncode == 0 and not result.stderr, result
                    raw = key.read_bytes()
                    assert re.fullmatch(rb'[0-9a-f]{64}', raw)
                    assert stat.S_IMODE(key.stat().st_mode) == stat.S_IMODE(output.stat().st_mode) == 0o600
                    actual = json.loads(output.read_bytes())
                    assert actual['consumers'] == [owner]
                    expected = dict(source_record, enabled=False)
                    assert actual['credentials'][0] == expected
                    expected = {k: v for k, v in source_record.items() if k not in ('secret', 'secretSha256')}
                    expected.update(id='new', secretSha256=hashlib.sha256(raw).hexdigest())
                    assert actual['credentials'][1] == expected
                    assert raw not in output.read_bytes()
                    assert run(tool, 'validate', output).returncode == 0
                    inspection = run(tool, 'inspect', output)
                    assert raw not in inspection.stdout + inspection.stderr
                    assert expected['secretSha256'].encode() not in inspection.stdout + inspection.stderr

    record = dict(id='old', consumerId=owner['id'], method='bearer', enabled=True,
                  secret=original_key, groups=['readers'], notBefore=1, expiresAt=2)
    snapshot = dict(version=1, consumers=[owner], credentials=[record])
    paused = dict(snapshot, consumers=[dict(owner, enabled=False)])
    result, output, _ = invoke(paused)
    assert result.returncode == 0 and json.loads(output.read_bytes())['consumers'] == paused['consumers']
    for old, new in [('missing', 'new'), ('old', 'old'), ('old', ''), ('old', 'bad id'),
                     ('old', 'x' * 65), ('bad id', 'new'), ('x' * 65, 'new'),
                     ('', 'new'), ('old', 'n\n'), ('old', 'é')]:
        result, output, key = invoke(snapshot, old, new)
        assert result.returncode == 2 and not output.exists() and not key.exists()
    for replacement in [dict(record, enabled=False), dict(record, method='basic', secret='u:p'),
                        dict(record, method='mtls', secret='a' * 64)]:
        result, output, key = invoke(dict(snapshot, credentials=[replacement]))
        assert result.returncode == 2 and not output.exists() and not key.exists()
    used = dict(record, id='used', enabled=False, secret='other-key')
    result, output, key = invoke(dict(snapshot, credentials=[record, used]), new='used')
    assert result.returncode == 2 and not output.exists() and not key.exists()
    # All credentials, including disabled ones, consume the retained-history capacity.
    full = [record] + [dict(id=f'o{i}', consumerId=owner['id'], method='bearer',
                            enabled=False, secret=f'k{i}') for i in range(63)]
    result, output, key = invoke(dict(snapshot, credentials=full))
    assert result.returncode == 2 and not output.exists() and not key.exists()
    assert run(tool, 'validate', root / f'rotation-{counter}.input').returncode == 0
    result, output, key = invoke(dict(snapshot, credentials=full[:-1]))
    assert result.returncode == 0 and len(json.loads(output.read_bytes())['credentials']) == 64
    result, output, key = invoke(b'{bad')
    assert result.returncode == 2 and not output.exists() and not key.exists()
    loose_input = private(root / 'rotation-loose-input', snapshot)
    loose_input.chmod(0o644)
    before = loose_input.read_bytes()
    output, key = root / 'rotation-loose-input.snapshot', root / 'rotation-loose-input.key'
    result = run(tool, 'rotate-key-verifier', loose_input, 'old', 'new', output, key)
    assert result.returncode == 2 and not result.stdout and not output.exists() and not key.exists()
    assert loose_input.read_bytes() == before
    quoted = dict(record, id='old"id')
    result, output, _ = invoke(dict(snapshot, credentials=[quoted]), old='old"id', new='new"id')
    assert result.returncode == 0 and json.loads(output.read_bytes())['credentials'][1]['id'] == 'new"id'
    result, output, key = invoke(dict(snapshot, credentials=[dict(record, groups=['unknown'])]))
    assert result.returncode == 2 and not output.exists() and not key.exists()
    alias = root / 'rotation-same-output'
    result, _, _ = invoke(snapshot, key_output=alias, snapshot_output=alias)
    assert result.returncode == 2 and not alias.exists()
    existing = private(root / 'rotation-existing', b'preserve')
    result, output, _ = invoke(snapshot, key_output=existing)
    assert result.returncode == 2 and not output.exists() and existing.read_bytes() == b'preserve'
    result, _, key = invoke(snapshot, snapshot_output=existing)
    assert result.returncode == 2 and not key.exists() and existing.read_bytes() == b'preserve'
    link = root / 'rotation-symlink'
    link.symlink_to(existing)
    result, output, _ = invoke(snapshot, key_output=link)
    assert result.returncode == 2 and not output.exists() and existing.read_bytes() == b'preserve'
    other = root / 'rotation-other-directory'
    other.mkdir(mode=0o700)
    result, output, key = invoke(snapshot, key_output=other / 'key')
    assert result.returncode == 2 and not output.exists() and not key.exists()
    loose = root / 'rotation-loose'
    loose.mkdir(mode=0o777)
    loose.chmod(0o777)
    result, output, key = invoke(snapshot, key_output=loose / 'key', snapshot_output=loose / 'snapshot')
    loose.chmod(0o700)
    assert result.returncode == 2 and not output.exists() and not key.exists()
    source = private(root / 'rotation-race.input', snapshot)
    before = source.read_bytes()
    output, key = root / 'rotation-race.snapshot', root / 'rotation-race.key'
    with ThreadPoolExecutor(max_workers=6) as workers:
        results = list(workers.map(lambda _: run(tool, 'rotate-key-verifier', source,
                                  'old', 'new', output, key), range(6)))
    assert sum(result.returncode == 0 for result in results) == 1
    assert all(result.returncode in (0, 2) and not result.stdout for result in results)
    assert source.read_bytes() == before
    raw = key.read_bytes()
    actual = json.loads(output.read_bytes())
    assert actual['credentials'][0] == dict(record, enabled=False)
    assert actual['credentials'][1]['secretSha256'] == hashlib.sha256(raw).hexdigest()
    assert all(raw not in result.stderr for result in results)


def test_credential_groups_preserve_and_reject_parent_removal(tool, root):
    key = 'a' * 64
    alice = dict(id='alice', enabled=True, groups=['staff', 'readers'])
    restricted = dict(id='read', consumerId='alice', method='bearer', secret=key,
                      enabled=True, groups=['readers'])
    inherited = dict(id='inherit', consumerId='alice', method='header', secret='header-key',
                     enabled=True)
    snapshot = dict(version=1, consumers=[alice], credentials=[restricted, inherited])
    source = private(root / 'groups-source.json', snapshot)
    patch = private(root / 'groups-noop.json', changes())
    applied = root / 'groups-applied.json'
    result = run(tool, 'apply', source, patch, applied)
    assert result.returncode == 0 and json.loads(applied.read_bytes()) == snapshot
    inspected = run(tool, 'inspect', applied)
    assert inspected.returncode == 0
    inspect_snapshot = json.loads(inspected.stdout)
    assert inspect_snapshot['credentials'][0]['groups'] == ['readers']
    assert 'groups' not in inspect_snapshot['credentials'][1]

    hashed = root / 'groups-hashed.json'
    result = run(tool, 'hash-keys', source, hashed)
    assert result.returncode == 2 and not hashed.exists(), 'weak header should reject whole conversion'
    # Convert a valid-profile header too; both credential group forms must survive.
    valid_snapshot = dict(snapshot)
    valid_snapshot['credentials'] = [restricted, dict(inherited, secret='b' * 64)]
    valid_source = private(root / 'groups-valid-hash-source.json', valid_snapshot)
    result = run(tool, 'hash-keys', valid_source, hashed)
    assert result.returncode == 0
    hashed_records = {item['id']: item for item in json.loads(hashed.read_bytes())['credentials']}
    assert hashed_records['read']['groups'] == ['readers']
    assert 'groups' not in hashed_records['inherit']

    removal = private(root / 'groups-remove-parent.json', changes(
        consumers=[dict(id='alice', enabled=True, groups=['staff'])]))
    rejected = root / 'groups-removal-rejected.json'
    result = run(tool, 'apply', source, removal, rejected)
    assert result.returncode == 2 and not result.stdout and not rejected.exists()
    narrowed = private(root / 'groups-narrow-and-remove.json', changes(
        consumers=[dict(id='alice', enabled=True, groups=['staff'])],
        credentials=[dict(restricted, groups=[])]))
    replacement = root / 'groups-removal-replacement.json'
    result = run(tool, 'apply', source, narrowed, replacement)
    assert result.returncode == 0
    final = json.loads(replacement.read_bytes())
    final_read = next(item for item in final['credentials'] if item['id'] == 'read')
    assert final_read['groups'] == []


def main(tool):
    assert run(tool, '--help').returncode == 0
    for args in [[], ['init'], ['apply'], ['inspect'], ['validate'], ['plan'],
                 ['plan', 'a'], ['plan', 'a', 'b', 'c'], ['init', 'a', 'b'],
                 ['apply', 'a', 'b', 'c', 'd'], ['unknown']]:
        result = run(tool, *args)
        assert result.returncode == 2 and not result.stdout
    with tempfile.TemporaryDirectory(prefix='rut-consumers-cli-') as directory:
        root = Path(directory)
        test_prune_credentials(tool, root)
        test_generated_keys(tool, root)
        test_time_window_metadata_survives_cli(tool, root)
        test_hash_keys(tool, root)
        test_generated_key_verifier(tool, root)
        test_rotated_key_verifier(tool, root)
        test_credential_groups_preserve_and_reject_parent_removal(tool, root)
        initial = root / 'initial.json'
        assert run(tool, 'init', initial).returncode == 0
        empty = json.loads(initial.read_bytes())
        assert empty == dict(version=1, consumers=[], credentials=[])
        assert stat.S_IMODE(initial.stat().st_mode) == 0o600
        assert run(tool, 'validate', initial).returncode == 0
        alice = dict(id='alice', enabled=True, groups=['staff'])
        key = dict(id='key-v1', consumerId='alice', method='bearer', secret='private-key-v1', enabled=True)
        patch = private(root / 'changes.json', changes([alice], [key]))
        active = root / 'active.json'
        result = run(tool, 'apply', initial, patch, active)
        assert result.returncode == 0 and not result.stdout and not result.stderr, result
        assert json.loads(active.read_bytes()) == dict(version=1, consumers=[alice], credentials=[key])
        assert json.loads(initial.read_bytes()) == empty
        inspected = run(tool, 'inspect', active)
        assert inspected.returncode == 0 and b'private-key' not in inspected.stdout + inspected.stderr
        identity = json.loads(inspected.stdout)
        assert identity['consumers'] == [alice]
        assert identity['credentials'] == [{k: v for k, v in key.items() if k != 'secret'}]
        mtls = dict(id='client-cert-v1', consumerId='alice', method='mtls',
                    secret='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
                    enabled=False)
        private(patch, changes([alice], [mtls]))
        mtls_snapshot = root / 'mtls.json'
        assert run(tool, 'apply', initial, patch, mtls_snapshot).returncode == 0
        assert run(tool, 'validate', mtls_snapshot).returncode == 0
        mtls_inspected = run(tool, 'inspect', mtls_snapshot)
        assert mtls_inspected.returncode == 0
        assert json.loads(mtls_inspected.stdout)['credentials'] == [
            {k: v for k, v in mtls.items() if k != 'secret'}]
        assert mtls['secret'].encode() not in mtls_inspected.stdout + mtls_inspected.stderr
        private(patch, changes([alice], [key]))
        # Preflight uses the complete runtime validator before showing metadata.
        # It creates no files, leaves inputs intact, and matches later inspection.
        before = {p.name: p.read_bytes() for p in root.iterdir() if p.is_file() and not p.is_symlink()}
        planned = run(tool, 'plan', initial, patch)
        assert planned.returncode == 0 and not planned.stderr
        assert planned.stdout == inspected.stdout
        assert b'private-key' not in planned.stdout + planned.stderr
        assert {p.name: p.read_bytes() for p in root.iterdir()
                if p.is_file() and not p.is_symlink()} == before
        # Rotation overlap, group replacement and explicit disable preserve IDs.
        next_key = dict(key, id='key-v2', secret='private-key-v2')
        private(patch, changes([dict(alice, groups=['readers'])], [next_key]))
        planned = run(tool, 'plan', active, patch)
        assert planned.returncode == 0 and b'private-key' not in planned.stdout
        preview = json.loads(planned.stdout)
        assert preview['consumers'][0]['groups'] == ['readers']
        assert [k['id'] for k in preview['credentials']] == ['key-v1', 'key-v2']
        assert all('secret' not in k for k in preview['credentials'])
        rotated = root / 'rotated.json'
        assert run(tool, 'apply', active, patch, rotated).returncode == 0
        assert run(tool, 'inspect', rotated).stdout == planned.stdout
        assert len(json.loads(rotated.read_bytes())['credentials']) == 2
        private(patch, changes(credentials=[dict(key, enabled=False)]))
        disabled = root / 'disabled.json'
        assert run(tool, 'apply', rotated, patch, disabled).returncode == 0
        assert not next(k for k in json.loads(disabled.read_bytes())['credentials'] if k['id'] == 'key-v1')['enabled']
        private(patch, changes(remove_credentials=['key-v1']))
        planned = run(tool, 'plan', disabled, patch)
        assert planned.returncode == 0
        assert [k['id'] for k in json.loads(planned.stdout)['credentials']] == ['key-v2']
        retired = root / 'retired.json'
        assert run(tool, 'apply', disabled, patch, retired).returncode == 0
        assert b'private-key-v1' not in retired.read_bytes()
        private(patch, changes(remove_credentials=['key-v2'], remove_consumers=['alice']))
        removed = root / 'removed.json'
        assert run(tool, 'apply', retired, patch, removed).returncode == 0
        assert json.loads(removed.read_bytes()) == empty
        # Invalid transactions cannot create output, alter input or leak secrets.
        invalid = [
            changes([alice, alice]), changes(credentials=[key, key]),
            changes(credentials=[dict(key, id='other')]),  # duplicate method/secret
            changes(credentials=[dict(key, consumerId='missing')]),
            changes(credentials=[dict(key, method='cookie')]),
            changes(credentials=[dict(key, secret='')]),
            changes(credentials=[dict(key, extra='private-invalid-field')]),
            changes([dict(alice, groups=['staff', 'staff'])]),
            changes(credentials=[dict(mtls, secret='A' * 64)]),
            changes([dict(alice, enabled=1)]), changes([dict(alice, id='bad id')]),
            changes([dict(alice, id='x' * 65)]), changes([dict(alice, groups=['x' * 129])]),
            changes(remove_consumers=['alice']),  # would leave an orphan
            changes(remove_credentials=['missing']), changes(remove_consumers=['missing']),
            changes(remove_credentials=['key-v1', 'key-v1']),
            changes(credentials=[key], remove_credentials=['key-v1']),
            changes([dict(alice, id=f'user{i}') for i in range(32)]),
            changes(credentials=[dict(key, id=f'key{i}', secret=f'private-key-{i}') for i in range(65)]),
            dict(consumers=[], credentials=[], removeConsumers=[]),
            dict(changes(), extra=[]), changes(remove_consumers=[1]),
            changes(remove_credentials=[{}]), dict(changes(), consumers={}),
            b'{"consumers":[],"consumers":[],"credentials":[],"removeConsumers":[],"removeCredentials":[]}',
            b'{"consumers":[{"id":"alice","id":"bob"}],"credentials":[],"removeConsumers":[],"removeCredentials":[]}',
            b'[]', b'null', b'{', b' ' * 8193,
        ]
        original = active.read_bytes()
        for value in invalid:
            private(patch, value)
            output = root / 'must-not-exist.json'
            result = run(tool, 'apply', active, patch, output)
            assert result.returncode == 2 and not result.stdout, (value, result)
            assert b'private-' not in result.stderr
            assert not output.exists() and active.read_bytes() == original
            planned = run(tool, 'plan', active, patch)
            assert planned.returncode == 2 and not planned.stdout, (value, planned)
            assert b'private-' not in planned.stderr
        # Decoded ID equality must replace, not append or miss a removal.
        private(patch, b'{"consumers":[],"credentials":[],"removeConsumers":[],"removeCredentials":["key-v\\u0031"]}')
        escaped = root / 'escaped.json'
        assert run(tool, 'apply', active, patch, escaped).returncode == 0
        assert not json.loads(escaped.read_bytes())['credentials']
        # Both capacity limits are reachable without granting excess records.
        private(patch, changes([dict(alice, id=f'c{i}') for i in range(32)]))
        capacity = root / 'capacity.json'
        assert run(tool, 'apply', initial, patch, capacity).returncode == 0
        private(patch, changes([alice], [dict(key, id=f'k{i}', secret=f's{i}') for i in range(64)]))
        credentials = root / 'credentials.json'
        assert run(tool, 'apply', initial, patch, credentials).returncode == 0
        assert len(json.loads(credentials.read_bytes())['credentials']) == 64
        # No replacement, even for aliases of input or racing administrators.
        private(patch, changes())
        assert run(tool, 'apply', active, patch, active).returncode == 2
        assert active.read_bytes() == original
        raced = root / 'raced.json'
        with ThreadPoolExecutor(max_workers=8) as workers:
            results = list(workers.map(lambda _: run(tool, 'apply', active, patch, raced), range(8)))
        assert sum(r.returncode == 0 for r in results) == 1
        assert all(r.returncode in (0, 2) for r in results)
        assert json.loads(raced.read_bytes()) == json.loads(original)
        assert stat.S_IMODE(raced.stat().st_mode) == 0o600
        link = root / 'link'
        link.symlink_to(active)
        fifo = root / 'fifo'
        os.mkfifo(fifo)
        public = private(root / 'public.json', original)
        public.chmod(0o644)
        for unsafe in [link, fifo, root, root / 'absent', public]:
            for operation in ['validate', 'inspect']:
                result = run(tool, operation, unsafe)
                assert result.returncode == 2 and not result.stdout
            assert run(tool, 'apply', active, unsafe, root / 'bad.json').returncode == 2
            for base, transaction in [(unsafe, patch), (active, unsafe)]:
                planned = run(tool, 'plan', base, transaction)
                assert planned.returncode == 2 and not planned.stdout
        for destination in [link, fifo, root, active]:
            assert run(tool, 'init', destination).returncode == 2
        untrusted = root / 'untrusted'
        untrusted.mkdir(mode=0o777)
        untrusted.chmod(0o777)
        assert run(tool, 'init', untrusted / 'snapshot').returncode == 2
        for malformed in [b'{}', b'null', b'{"version":1,"consumers":[],"credentials":[],"extra":1}',
                          b'{"version":1,"consumers":[],"credentials":[],"version":1}']:
            private(patch, malformed)
            result = run(tool, 'inspect', patch)
            assert result.returncode == 2 and not result.stdout
        # Inspect can add a newline to a full-size registry without credentials.
        full = dict(version=1, consumers=[dict(id=f'c{i}', enabled=True,
                    groups=[f'g{j}-' + 'x' * 100 for j in range(16)]) for i in range(4)],
                    credentials=[])
        encode = lambda: json.dumps(full, separators=(',', ':')).encode()
        needed = 8192 - len(encode())
        for consumer in full['consumers']:
            for i, group in enumerate(consumer['groups']):
                count = min(needed, 128 - len(group))
                consumer['groups'][i] += 'x' * count
                needed -= count
        assert needed == 0 and len(encode()) == 8192
        private(patch, encode())
        assert run(tool, 'validate', patch).returncode == 0
        inspected = run(tool, 'inspect', patch)
        assert inspected.returncode == 0 and len(inspected.stdout) == 8193
        assert json.loads(inspected.stdout) == full
        capacity_output = root / 'generated-over-capacity.json'
        capacity_key = run(tool, 'generate-key', patch, 'c0', 'capacity-key', 'bearer', capacity_output)
        assert capacity_key.returncode == 2 and not capacity_key.stdout
        assert not capacity_output.exists()
        no_changes = private(root / 'no-changes.json', changes())
        planned = run(tool, 'plan', patch, no_changes)
        assert planned.returncode == 0 and planned.stdout == inspected.stdout
        # File-byte bounds include any whitespace; parsing still uses runtime limits.
        private(patch, original + b' ' * (8192 - len(original)))
        assert run(tool, 'validate', patch).returncode == 0
        for value in [b'', original + b' ' * (8193 - len(original))]:
            private(patch, value)
            assert run(tool, 'validate', patch).returncode == 2
        assert not list(root.glob('.rut-consumers-*'))
    print('PASS: Consumer admin lifecycle, strict atomic updates, redaction, capacity and private no-replace files')


if __name__ == '__main__':
    main(sys.argv[1])
