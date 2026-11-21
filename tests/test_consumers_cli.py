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


def test_deployment_policy(tool, root):
    alice = dict(id='alice', enabled=True, groups=['operators'])
    disabled = dict(id='disabled', enabled=False, groups=[])
    digest = hashlib.sha256(b'fixture-verifier').hexdigest()
    key = dict(id='key', consumerId='alice', method='bearer', enabled=True,
               secretSha256=digest, notBefore=100, expiresAt=200, groups=['operators'])
    parked = dict(key, id='parked', method='header', enabled=False)
    raw = dict(key, secret='private-policy-fixture')
    del raw['secretSha256']
    hidden = [digest.encode(), raw['secret'].encode(), b'fixture-password']
    source = root / 'policy-source.json'
    profile = root / 'deployment-policy.json'

    def check(rules, *, records=None, consumers=None, now=120, ok=False, rule=None):
        snapshot = dict(version=1, consumers=[alice, disabled] if consumers is None else consumers,
                        credentials=[key, parked] if records is None else records)
        private(source, snapshot)
        private(profile, rules)
        before = (source.read_bytes(), profile.read_bytes(), set(root.iterdir()))
        result = run(tool, 'check-policy', source, profile, now)
        assert result.returncode == (0 if ok else 2), (rules, result)
        assert not result.stdout
        assert all(secret not in result.stderr for secret in hidden)
        assert (source.read_bytes(), profile.read_bytes(), set(root.iterdir())) == before
        if ok:
            assert not result.stderr
        if rule:
            assert result.stderr.endswith(rule.encode() + b'\n')

    check({'unknown': True})
    check(br'{"requireHashedKeys":false,"requireHashed\u004beys":true}')
    check({})
    check([])
    check({'requireHashedKeys': True}, now=0)
    check({'requireHashedKeys': True}, now='9223372036854775808')
    check({'requireHashedKeys': True}, records=[dict(key, consumerId='missing')])
    profile.chmod(0o644)
    assert run(tool, 'check-policy', source, profile, 120).returncode == 2
    assert run(tool, 'check-policy', source, profile).returncode == 2

    check({'requireHashedKeys': True}, ok=True)
    check({'requireHashedKeys': False}, ok=True, records=[raw, parked])
    check({'requireHashedKeys': True}, records=[raw, parked], rule='requireHashedKeys')
    check({'requireHashedKeys': True}, records=[dict(raw, enabled=False)], rule='requireHashedKeys')
    check({'requireHashedKeys': 1}, rule='requireHashedKeys')
    check({'allowedMethods': ['bearer', 'header']}, ok=True)
    check({'allowedMethods': ['bearer']}, rule='allowedMethods')
    for invalid in ([], ['bearer', 'bearer'], ['cookie'], ['bearer', 1], 'bearer'):
        check({'allowedMethods': invalid}, rule='allowedMethods')
    basic = dict(raw, method='basic', secret='operator:fixture-password')
    mtls = dict(raw, method='mtls', secret='b' * 64)
    check({'allowedMethods': ['basic']}, ok=True, records=[basic])
    check({'allowedMethods': ['mtls']}, ok=True, records=[mtls])
    check({'allowedMethods': ['header']}, records=[basic], rule='allowedMethods')


def changes(consumers=(), credentials=(), remove_consumers=(), remove_credentials=()):
    return dict(consumers=list(consumers), credentials=list(credentials),
                removeConsumers=list(remove_consumers), removeCredentials=list(remove_credentials))


def test_apply_checked(tool, root):
    consumer = dict(id='checked-owner', enabled=True, groups=['staff'])
    raw = dict(id='checked-raw', consumerId=consumer['id'], method='bearer',
               enabled=True, secret='checked-private-secret')
    digest = hashlib.sha256(b'checked-fixture').hexdigest()
    hashed = dict(id='checked-verifier', consumerId=consumer['id'], method='header',
                  enabled=True, secretSha256=digest, groups=['staff'])
    source = private(root / 'checked-input.json',
                     dict(version=1, consumers=[consumer], credentials=[raw]))
    policy = private(root / 'checked-policy.json',
                     dict(requireHashedKeys=True, allowedMethods=['header']))
    patch = private(root / 'checked-changes.json', changes())
    output = root / 'checked-output.json'
    source_bytes = source.read_bytes()

    def apply_checked(now=120, expected=2):
        inputs = [path.read_bytes() for path in (source, patch, policy)]
        files = set(root.iterdir())
        result = run(tool, 'apply-checked', source, patch, policy, now, output)
        assert result.returncode == expected, result
        assert not result.stdout
        assert all(secret not in result.stderr for secret in (raw['secret'].encode(), digest.encode()))
        assert [path.read_bytes() for path in (source, patch, policy)] == inputs
        if expected != 0:
            assert set(root.iterdir()) == files
        return result

    assert b'requireHashedKeys' in apply_checked().stderr
    assert not output.exists()
    updated = changes(credentials=[hashed], remove_credentials=[raw['id']])
    private(patch, updated)
    assert b'evaluation time' in apply_checked(now=0).stderr
    policy.chmod(0o644)
    assert b'invalid private' in apply_checked().stderr
    policy.chmod(0o600)
    assert not output.exists()

    assert not apply_checked(expected=0).stderr
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert json.loads(output.read_bytes()) == dict(version=1, consumers=[consumer],
                                                  credentials=[hashed])
    assert run(tool, 'check-policy', output, policy, 120).returncode == 0
    published = output.read_bytes()
    apply_checked()
    assert output.read_bytes() == published
    assert source.read_bytes() == source_bytes


def test_targeted_registry_commands(tool, root):
    alice = dict(id='ali"ce', enabled=True, groups=['staff', 'readers'])
    bob = dict(id='bob', enabled=True, groups=['readers'])
    vacant = dict(id='vacant', enabled=False, groups=[])
    raw = dict(id='raw', consumerId=alice['id'], method='bearer',
               enabled=True, secret='private-targeted-fixture')
    digest = hashlib.sha256(b'targeted-verifier-fixture').hexdigest()
    parked = dict(id='parked', consumerId=alice['id'], method='header',
                  enabled=False, secretSha256=digest, groups=['readers'],
                  notBefore=10, expiresAt=100)
    inherited = dict(id='inherited', consumerId=alice['id'], method='header',
                     enabled=False, secret='private-inherited-fixture')
    consumers = [alice, bob, vacant]
    records = [raw, parked, inherited]
    snapshot = dict(version=1, consumers=consumers, credentials=records)
    source = private(root / 'targeted-input.json', snapshot)
    original = source.read_bytes()
    secrets = [raw['secret'].encode(), digest.encode(), inherited['secret'].encode()]

    def check_output(result):
        for secret in secrets:
            assert secret not in result.stdout and secret not in result.stderr

    def inspect(command, record_id, expected):
        result = run(tool, command, source, record_id)
        check_output(result)
        if expected is None:
            assert result.returncode == 2 and not result.stdout
        else:
            assert result.returncode == 0 and not result.stderr, result
            assert json.loads(result.stdout) == expected

    inspect('inspect-consumer', alice['id'], alice)
    inspect('inspect-consumer', 'missing', None)
    for record in records:
        expected = {key: value for key, value in record.items() if key not in ('secret', 'secretSha256')}
        inspect('inspect-credential', record['id'], expected)
    inspect('inspect-credential', 'missing', None)
    inspect('inspect-credential', alice['id'], None)
    assert source.read_bytes() == original


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


def test_snapshot_diff(tool, root):
    def empty():
        return dict(consumers=dict(added=[], removed=[], changed=[]),
                    credentials=dict(added=[], removed=[], changed=[]))

    def redact(record):
        return {key: value for key, value in record.items() if key not in ('secret', 'secretSha256')}

    counter = 0
    def compare(before, after, expected=None):
        nonlocal counter
        counter += 1
        left = private(root / f'diff-{counter}.before', before)
        right = private(root / f'diff-{counter}.after', after)
        originals = left.read_bytes(), right.read_bytes()
        names = set(root.iterdir())
        result = run(tool, 'diff', left, right)
        assert left.read_bytes() == originals[0] and right.read_bytes() == originals[1]
        assert set(root.iterdir()) == names
        if expected is None:
            assert result.returncode == 2 and not result.stdout
        else:
            assert result.returncode == 0 and not result.stderr and result.stdout.endswith(b'\n'), result
            assert json.loads(result.stdout) == expected
            assert b'"secret"' not in result.stdout and b'"secretSha256"' not in result.stdout
            for value in (before, after):
                value = json.loads(value) if isinstance(value, bytes) else value
                for record in value['credentials']:
                    secret = record.get('secret', record.get('secretSha256')).encode()
                    assert secret not in result.stdout + result.stderr
            repeated = run(tool, 'diff', left, right)
            assert repeated.stdout == result.stdout and repeated.stderr == result.stderr
        return result

    owner = dict(id='alice', enabled=True, groups=['readers', 'staff'])
    record = dict(id='key', consumerId='alice', method='bearer', secret='private-key-text', enabled=True)
    before = dict(version=1, consumers=[owner], credentials=[record])
    compare(before, before, empty())
    other = dict(record, id='other', secret='other-private-key')
    ordered = dict(before, credentials=[record, other])
    reordered = dict(before, consumers=[dict(groups=['staff', 'readers'], enabled=True, id='alice')],
                     credentials=[other, record])
    escaped = json.dumps(reordered).replace('alice', r'\u0061lice').replace('private-key-text', r'\u0070rivate-key-text').encode()
    compare(ordered, escaped, empty())

    def changed(replacement, key_changed=False, representation_changed=False, source=record):
        expected = empty()
        expected['credentials']['changed'] = [dict(before=redact(source), after=redact(replacement),
            keyChanged=key_changed, keyRepresentationChanged=representation_changed)]
        return expected

    # Metadata-only edits, explicit empty subsets, and explicit zero windows are audit changes.
    for replacement in (dict(record, enabled=False), dict(record, groups=[]),
                        dict(record, groups=['readers']), dict(record, notBefore=0),
                        dict(record, expiresAt=0), dict(record, notBefore=1, expiresAt=2)):
        compare(before, dict(before, credentials=[replacement]), changed(replacement))
    zero = dict(before, credentials=[dict(record, notBefore=0)])
    negative_zero = json.dumps(zero).replace('"notBefore": 0', '"notBefore": -0').encode()
    compare(zero, negative_zero)
    paused = dict(record, enabled=False)
    compare(dict(before, credentials=[paused]), dict(before, credentials=[record]), changed(record, source=paused))

    for method in ('bearer', 'header'):
        for raw in ('private-key-text', 'x' * 4096):
            source = dict(record, method=method, secret=raw)
            converted = {key: value for key, value in source.items() if key != 'secret'}
            converted['secretSha256'] = hashlib.sha256(raw.encode()).hexdigest()
            compare(dict(before, credentials=[source]), dict(before, credentials=[converted]),
                    changed(converted, representation_changed=True, source=source))
            compare(dict(before, credentials=[converted]), dict(before, credentials=[source]),
                    changed(source, representation_changed=True, source=converted))
            compare(dict(before, credentials=[converted]), dict(before, credentials=[converted]), empty())
            replacement = dict(source, secret='different-private-material')
            compare(dict(before, credentials=[source]), dict(before, credentials=[replacement]),
                    changed(replacement, key_changed=True, source=source))
            different_hash = dict(converted, secretSha256=hashlib.sha256(b'different-private-material').hexdigest())
            compare(dict(before, credentials=[source]), dict(before, credentials=[different_hash]),
                    changed(different_hash, key_changed=True, representation_changed=True, source=source))
    for method, old, new in [('basic', 'user:private-password', 'user:other-password'),
                              ('mtls', 'a' * 64, 'b' * 64)]:
        source, replacement = dict(record, method=method, secret=old), dict(record, method=method, secret=new)
        compare(dict(before, credentials=[source]), dict(before, credentials=[replacement]),
                changed(replacement, key_changed=True, source=source))
    replacement = dict(record, method='header')
    compare(before, dict(before, credentials=[replacement]), changed(replacement, key_changed=True))

    bob = dict(id='bob', enabled=False, groups=[])
    cara = dict(id='cara', enabled=True, groups=[])
    removed = dict(record, id='removed', consumerId='bob', enabled=False, secret='removed-private-key')
    added = dict(record, id='added', consumerId='cara', secret='added-private-key')
    disabled = dict(record, enabled=False)
    expected = empty()
    expected['consumers'].update(added=[cara], removed=[bob])
    expected['credentials'].update(added=[redact(added)], removed=[redact(removed)],
        changed=[dict(before=redact(record), after=redact(disabled), keyChanged=False, keyRepresentationChanged=False)])
    compare(dict(before, consumers=[owner, bob], credentials=[removed, record]),
            dict(before, consumers=[cara, owner], credentials=[disabled, added]), expected)

    # Full valid32/64 snapshots produce a complete structured output larger than one input.
    full = dict(version=1, consumers=[dict(id=f'c{i}', enabled=True, groups=[]) for i in range(32)],
                credentials=[dict(id=f'k{i}', consumerId=f'c{i % 32}', method='bearer',
                                  secret=f'private-material-{i}', enabled=True) for i in range(64)])
    updated = dict(version=1, consumers=[dict(item, enabled=False) for item in full['consumers']],
                   credentials=[dict(item, enabled=False) for item in full['credentials']])
    expected = empty()
    expected['consumers']['changed'] = [dict(before=a, after=b) for a, b in zip(full['consumers'], updated['consumers'])]
    expected['credentials']['changed'] = [dict(before=redact(a), after=redact(b), keyChanged=False,
        keyRepresentationChanged=False) for a, b in zip(full['credentials'], updated['credentials'])]
    encoded = [json.dumps(value, separators=(',', ':')).encode() for value in (full, updated)]
    assert all(len(value) <= 8192 for value in encoded)
    result = compare(*encoded, expected)
    assert len(result.stdout) > 8192

    for invalid in (b'{bad', dict(before, credentials=[dict(record, consumerId='missing')]),
                    dict(before, credentials=[record, record]),
                    dict(before, credentials=[dict(record, notBefore=2, expiresAt=1)])):
        compare(before, invalid)
        compare(invalid, before)
    valid_path = private(root / 'diff-private-valid', before)
    loose = private(root / 'diff-private-loose', before)
    loose.chmod(0o644)
    link = root / 'diff-private-link'
    link.symlink_to(valid_path)
    for invalid in (loose, link, root / 'diff-missing', root):
        for left, right in ((valid_path, invalid), (invalid, valid_path)):
            result = run(tool, 'diff', left, right)
            assert result.returncode == 2 and not result.stdout
            assert record['secret'].encode() not in result.stderr


def test_provision_key_verifier(tool, root):
    work = root / 'provision-profile'
    work.mkdir(mode=0o700)
    empty = dict(version=1, consumers=[], credentials=[])
    source = private(work / 'source.json', empty)
    consumer = dict(id='new"owner', enabled=True, groups=['readers', 'writers'])
    credential = dict(id='first-key', consumerId=consumer['id'], method='bearer', enabled=True,
                      groups=['readers'], notBefore=1, expiresAt=9223372036854775807)
    counter = 0

    def provision(profile, expected=None, source_path=source, destinations=None, env=None):
        nonlocal counter
        counter += 1
        profile_path = private(work / f'profile-{counter}.json', profile)
        snapshot, key = destinations or (work / f'output-{counter}.json', work / f'key-{counter}')
        before, profile_before = source_path.read_bytes(), profile_path.read_bytes()
        result = subprocess.run([tool, 'provision-key-verifier', str(source_path), str(profile_path),
                                 str(snapshot), str(key)], capture_output=True, timeout=10, env=env)
        assert source_path.read_bytes() == before and profile_path.read_bytes() == profile_before
        assert not result.stdout and b'secret-material' not in result.stderr
        if expected is None:
            assert result.returncode == 2, result
            assert not snapshot.exists() and not key.exists()
            return result
        assert result.returncode == 0 and not result.stderr, result
        material = key.read_bytes()
        assert len(material) == 64 and re.fullmatch(rb'[0-9a-f]{64}', material)
        assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in (snapshot, key))
        assert material not in snapshot.read_bytes()
        value = json.loads(snapshot.read_bytes())
        record = value['credentials'][-1]
        assert record.pop('secretSha256') == hashlib.sha256(material).hexdigest()
        assert 'secret' not in record and record == expected['credentials'][-1]
        assert value == expected
        assert run(tool, 'validate', snapshot).returncode == 0
        inspection = run(tool, 'inspect', snapshot)
        assert inspection.returncode == 0 and material not in inspection.stdout + inspection.stderr
        return snapshot, key

    provision(dict(consumer=consumer, credential=credential),
              dict(version=1, consumers=[consumer], credentials=[credential]))
    existing = dict(version=1, consumers=[consumer, dict(id='paused', enabled=False, groups=[])],
                    credentials=[dict(id='retired', consumerId=consumer['id'], method='header',
                                      enabled=False, secret='old-private-key')])
    existing_source = private(work / 'existing.json', existing)
    for method in ('bearer', 'header'):
        for policy in ({}, dict(groups=[]), dict(groups=['writers'], notBefore=0, expiresAt=0),
                       dict(groups=['readers'], notBefore=10, expiresAt=11),
                       dict(notBefore=9223372036854775807), dict(expiresAt=1)):
            record = dict(id='existing-key', consumerId=consumer['id'], method=method, enabled=True, **policy)
            provision(dict(credential=record),
                      dict(existing, credentials=existing['credentials'] + [record]), existing_source)
    paused = dict(id='paused-key', consumerId='paused', method='header', enabled=False, groups=[])
    provision(dict(credential=paused),
              dict(existing, credentials=existing['credentials'] + [paused]), existing_source)
    staged_consumer = dict(consumer, enabled=False)
    staged_record = dict(credential, enabled=False)
    provision(dict(consumer=staged_consumer, credential=staged_record),
              dict(version=1, consumers=[staged_consumer], credentials=[staged_record]))

    invalid = [dict(), dict(consumer=consumer), [], dict(consumer=None, credential=credential),
               dict(consumer=consumer, credential=credential, unknown=True),
               dict(consumer=dict(consumer, unknown=True), credential=credential),
               dict(consumer=dict(consumer, id='different'), credential=credential),
               dict(consumer=consumer, credential=dict(credential, consumerId='different'))]
    for field, value in (('secret', 'secret-material'), ('secretSha256', 'a' * 64),
                         ('unknown', True), ('method', 'basic'), ('method', 'mtls'),
                         ('method', 'other'), ('enabled', 1), ('id', ''), ('id', 'a' * 65),
                         ('consumerId', 'missing'), ('groups', ['absent']),
                         ('groups', ['readers', 'readers']), ('groups', 'readers'),
                         ('notBefore', -1), ('expiresAt', '10'), ('expiresAt', 1)):
        invalid.append(dict(consumer=consumer, credential=dict(credential, **{field: value})))
    for field in ('id', 'consumerId', 'method', 'enabled'):
        incomplete = dict(credential)
        incomplete.pop(field)
        invalid.append(dict(consumer=consumer, credential=incomplete))
    for profile in invalid:
        provision(profile)
    for key in ('credential', 'consumer'):
        original = json.dumps(dict(consumer=consumer, credential=credential))
        raw = (original[:-1] + ',' + json.dumps(key) + ':' + json.dumps(
            credential if key == 'credential' else consumer) + '}').encode()
        provision(raw)
    duplicate = json.dumps(dict(consumer=consumer, credential=credential)).replace(
        '"first-key"', '"first-key", "id": "second-key"')
    provision(duplicate.encode())
    provision(dict(consumer=consumer, credential=credential), source_path=existing_source)
    provision(dict(credential=dict(credential, id='retired')), source_path=existing_source)
    malformed = private(work / 'malformed-source.json', dict(existing, unknown=True))
    provision(dict(credential=credential), source_path=malformed)
    provision(b'x' * 8193)

    # Both schema cardinality limits are checked against the complete replacement.
    full_consumers = [dict(id=f'c{i}', enabled=True, groups=[]) for i in range(32)]
    full = private(work / 'full-consumers.json', dict(version=1, consumers=full_consumers, credentials=[]))
    provision(dict(consumer=consumer, credential=credential), source_path=full)
    many = [dict(id=f'k{i}', consumerId=consumer['id'], method='header', enabled=False,
                 secret=f'key-{i}') for i in range(64)]
    full = private(work / 'full-credentials.json', dict(version=1, consumers=[consumer], credentials=many))
    assert run(tool, 'validate', full).returncode == 0
    provision(dict(credential=credential), source_path=full)
    available = private(work / 'one-slot.json', dict(version=1, consumers=[consumer], credentials=many[:-1]))
    provision(dict(credential=credential),
              dict(version=1, consumers=[consumer], credentials=many[:-1] + [credential]), available)

    profile_path = private(work / 'private-profile.json', dict(consumer=consumer, credential=credential))
    snapshot, key = work / 'guard-output.json', work / 'guard-key'
    command = [tool, 'provision-key-verifier', source, profile_path, snapshot, key]
    profile_path.chmod(0o644)
    assert run(*command).returncode == 2 and not snapshot.exists() and not key.exists()
    profile_path.chmod(0o600)
    symlink = work / 'profile-link'
    symlink.symlink_to(profile_path)
    assert run(tool, 'provision-key-verifier', source, symlink, snapshot, key).returncode == 2
    for first, second in ((source, key), (snapshot, profile_path), (snapshot, snapshot)):
        assert run(tool, 'provision-key-verifier', source, profile_path, first, second).returncode == 2
    assert not snapshot.exists() and not key.exists()
    other = work / 'other'
    other.mkdir(mode=0o700)
    assert run(tool, 'provision-key-verifier', source, profile_path, snapshot, other / 'key').returncode == 2
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: run(*command), range(2)))
    assert sorted(result.returncode for result in results) == [0, 2]
    assert all(not result.stdout for result in results)
    winner = json.loads(snapshot.read_bytes())
    assert winner['credentials'][0]['secretSha256'] == hashlib.sha256(key.read_bytes()).hexdigest()

    shim = root / 'linkat-fault.so'
    marker = root / 'preload-capability.marker'
    if shim.exists() and marker.exists():
        for fail_at in (1, 2):
            failed_snapshot, failed_key = work / f'fault-{fail_at}.json', work / f'fault-{fail_at}.key'
            env = dict(os.environ, LD_PRELOAD=str(shim), RUT_TEST_LINKAT_FAIL_AT=str(fail_at))
            result = subprocess.run([tool, 'provision-key-verifier', str(source), str(profile_path),
                                     str(failed_snapshot), str(failed_key)], capture_output=True,
                                    timeout=10, env=env)
            assert result.returncode == 2 and not result.stdout and not failed_snapshot.exists()
            assert failed_key.exists() == (fail_at == 2)
            if failed_key.exists():
                assert failed_key.read_bytes() not in result.stderr
    for args in ([], ['a'], ['a', 'b'], ['a', 'b', 'c'], ['a', 'b', 'c', 'd', 'e']):
        assert run(tool, 'provision-key-verifier', *args).returncode == 2


def test_targeted_metadata(tool, root):
    work = root / 'targeted-metadata'
    work.mkdir(mode=0o700)
    consumers = [dict(id='alice"id', enabled=True, groups=['staff', 'readers']),
                 dict(id='paused', enabled=False, groups=[])]
    credentials = []
    for index, method in enumerate(('bearer', 'header', 'basic', 'mtls', 'bearer', 'header')):
        record = dict(id=f'credential-{index}', consumerId='alice"id', method=method,
                      enabled=index != 4)
        material = ('user:private-password' if method == 'basic' else
                    'a' * 64 if method == 'mtls' else f'private-key-{index}')
        if index >= 4:
            record['secretSha256'] = hashlib.sha256(material.encode()).hexdigest()
        else:
            record['secret'] = material
        if index % 2 == 0:
            record.update(groups=['readers'], notBefore=1, expiresAt=9223372036854775807)
        credentials.append(record)
    initial = dict(version=1, consumers=consumers, credentials=credentials)
    source = private(work / 'source.json', initial)
    groups = private(work / 'groups.json', ['readers', 'staff', 'writers'])
    counter = 0
    def update(command, identity, value, expected=None, input_path=source, output_path=None, env=None):
        nonlocal counter
        counter += 1
        output = output_path or work / f'updated-{counter}.json'
        before = input_path.read_bytes()
        result = subprocess.run([tool, command, str(input_path), identity, str(value), str(output)],
                                capture_output=True, timeout=10, env=env)
        assert not result.stdout and input_path.read_bytes() == before
        for record in credentials:
            assert record.get('secret', record.get('secretSha256')).encode() not in result.stderr
        if expected is None:
            assert result.returncode == 2 and not output.exists(), result
        else:
            assert result.returncode == 0 and not result.stderr, result
            assert json.loads(output.read_bytes()) == expected
            assert stat.S_IMODE(output.stat().st_mode) == 0o600
            assert run(tool, 'validate', output).returncode == 0
        return output

    assert run(tool, 'validate', source).returncode == 0
    for enabled in (False, True):
        expected = json.loads(json.dumps(initial))
        expected['consumers'][0]['enabled'] = enabled
        changed = update('set-consumer-enabled', consumers[0]['id'], str(enabled).lower(), expected)
        restored = update('set-consumer-enabled', consumers[0]['id'], 'true', initial, changed)
        assert json.loads(restored.read_bytes()) == initial
    for index, record in enumerate(credentials):
        for enabled in (False, True):
            expected = json.loads(json.dumps(initial))
            expected['credentials'][index]['enabled'] = enabled
            update('set-credential-enabled', record['id'], str(enabled).lower(), expected)
    for index, record in enumerate(credentials):
        expected = json.loads(json.dumps(initial))
        expected['credentials'][index].update(notBefore=10, expiresAt=20)
        out = work / f'window-{index}.json'
        result = run(tool, 'set-credential-window', source, record['id'], '10', '20', out)
        assert result.returncode == 0 and not result.stdout and not result.stderr
        assert json.loads(out.read_bytes()) == expected
        assert stat.S_IMODE(out.stat().st_mode) == 0o600
        assert run(tool, 'validate', out).returncode == 0
        reset = work / f'window-reset-{index}.json'
        assert run(tool, 'set-credential-window', out, record['id'], '0', '0', reset).returncode == 0
        expected['credentials'][index].update(notBefore=0, expiresAt=0)
        assert json.loads(reset.read_bytes()) == expected
    for start, end in (('', '0'), ('-1', '0'), ('+1', '0'), ('01', '0'),
                       (' 1', '0'), ('0', '1.0'), ('0', '9223372036854775808'),
                       ('10', '10'), ('11', '10')):
        out = work / 'invalid-window.json'
        result = run(tool, 'set-credential-window', source, credentials[0]['id'], start, end, out)
        assert result.returncode == 2 and not result.stdout and not out.exists()
        assert b'private-key' not in result.stderr
    for index, (start, end) in enumerate((('0', '1'), ('1', '0'), ('0', '9223372036854775807'))):
        out = work / f'window-bound-{index}.json'
        assert run(tool, 'set-credential-window', source, credentials[0]['id'], start, end, out).returncode == 0
        value = json.loads(out.read_bytes())['credentials'][0]
        assert value['notBefore'] == int(start) and value['expiresAt'] == int(end)
    raced = work / 'window-race.json'
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: run(tool, 'set-credential-window', source,
                                                   credentials[0]['id'], '1', '2', raced), range(2)))
    assert sorted(result.returncode for result in results) == [0, 2]
    assert json.loads(raced.read_bytes())['credentials'][0]['expiresAt'] == 2
    for args in ([], ['a'], ['a', 'b'], ['a', 'b', 'c'], ['a', 'b', 'c', 'd'],
                 ['a', 'b', 'c', 'd', 'e', 'f']):
        assert run(tool, 'set-credential-window', *args).returncode == 2
    source.chmod(0o644)
    out = work / 'insecure-window.json'
    assert run(tool, 'set-credential-window', source, credentials[0]['id'], '1', '2', out).returncode == 2
    assert not out.exists()
    source.chmod(0o600)
    out = work / 'unknown-window.json'
    assert run(tool, 'set-credential-window', source, 'missing', '1', '2', out).returncode == 2
    assert not out.exists()
    assert run(tool, 'set-credential-window', source, credentials[0]['id'], '1', '2', source).returncode == 2
    assert json.loads(source.read_bytes()) == initial
    paused = json.loads(json.dumps(initial))
    paused['consumers'][1]['enabled'] = True
    update('set-consumer-enabled', 'paused', 'true', paused)
    changed_groups = dict(initial, consumers=[dict(consumers[0], groups=['readers', 'staff', 'writers']), consumers[1]])
    update('set-consumer-groups', consumers[0]['id'], groups, changed_groups)
    assert json.loads(groups.read_bytes()) == ['readers', 'staff', 'writers']
    # Removing a group referenced even by a disabled credential is an invalid transaction.
    only_staff = private(work / 'only-staff.json', ['staff'])
    update('set-consumer-groups', consumers[0]['id'], only_staff)
    narrowed = json.loads(json.dumps(initial))
    for record in narrowed['credentials']:
        if 'groups' in record:
            record['groups'] = []
    narrowed_source = private(work / 'narrowed.json', narrowed)
    empty = private(work / 'empty.json', [])
    expected = dict(narrowed, consumers=[dict(consumers[0], groups=[]), consumers[1]])
    update('set-consumer-groups', consumers[0]['id'], empty, expected, narrowed_source)
    for value in (['duplicate', 'duplicate'], [''], ['a' * 129], ['a b'], [True], {}, None,
                  [f'g{i}' for i in range(17)], b'["readers"] trailing', b'['):
        invalid = private(work / 'invalid-groups.json', value)
        update('set-consumer-groups', consumers[0]['id'], invalid)
    for command, identity, value in (
        ('set-consumer-enabled', 'missing', 'true'),
        ('set-credential-enabled', 'missing', 'false'),
        ('set-consumer-groups', 'missing', groups),
        ('set-consumer-enabled', '', 'false'),
        ('set-credential-enabled', 'x' * 65, 'true')):
        update(command, identity, value)
    for command, identity in (('set-consumer-enabled', consumers[0]['id']),
                              ('set-credential-enabled', credentials[0]['id'])):
        for value in ('True', 'FALSE', '1', '0', ' true', 'true ', '', 'null'):
            update(command, identity, value)
    invalid_source = private(work / 'invalid-source.json', dict(initial, unknown=True))
    for command, identity, value in (
        ('set-consumer-enabled', consumers[0]['id'], 'false'),
        ('set-credential-enabled', credentials[0]['id'], 'false'),
        ('set-consumer-groups', consumers[0]['id'], groups)):
        update(command, identity, value, input_path=invalid_source)
        source.chmod(0o644)
        update(command, identity, value)
        source.chmod(0o600)
        link = work / 'source-link'
        if not link.exists():
            link.symlink_to(source)
        update(command, identity, value, input_path=link)
    only_disabled_reference = json.loads(json.dumps(narrowed))
    only_disabled_reference['credentials'][4]['groups'] = ['readers']
    disabled_reference = private(work / 'disabled-reference.json', only_disabled_reference)
    update('set-consumer-groups', consumers[0]['id'], only_staff, input_path=disabled_reference)
    large = dict(version=1, consumers=[dict(id='large', enabled=True, groups=[])],
                 credentials=[dict(id='large-a', consumerId='large', method='bearer', enabled=True,
                                   secret='a' * 4096),
                              dict(id='large-b', consumerId='large', method='header', enabled=True,
                                   secret='b' * 2900)])
    large_source = private(work / 'large-source.json', large)
    assert run(tool, 'validate', large_source).returncode == 0
    large_groups = private(work / 'large-groups.json', [f'g{i:02}' + 'x' * 125 for i in range(16)])
    update('set-consumer-groups', 'large', large_groups, input_path=large_source)
    # Private input, no-replace output, and directory ownership/mode use shared guards.
    groups.chmod(0o644)
    update('set-consumer-groups', consumers[0]['id'], groups)
    groups.chmod(0o600)
    linked_groups = work / 'groups-link'
    linked_groups.symlink_to(groups)
    update('set-consumer-groups', consumers[0]['id'], linked_groups)
    assert run(tool, 'set-consumer-enabled', source, consumers[0]['id'], 'false', source).returncode == 2
    existing = private(work / 'existing.json', b'private-sentinel')
    assert run(tool, 'set-consumer-groups', source, consumers[0]['id'], groups, existing).returncode == 2
    assert existing.read_bytes() == b'private-sentinel'
    unsafe = work / 'unsafe'
    unsafe.mkdir(mode=0o700)
    unsafe.chmod(0o777)
    update('set-consumer-enabled', consumers[0]['id'], 'false', output_path=unsafe / 'output')
    unsafe.chmod(0o700)
    raced = work / 'race.json'
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: run(tool, 'set-consumer-enabled', source,
                                                   consumers[0]['id'], 'false', raced), range(2)))
    assert sorted(result.returncode for result in results) == [0, 2]
    assert all(not result.stdout for result in results)
    assert json.loads(raced.read_bytes())['consumers'][0]['enabled'] is False
    shim, marker = root / 'linkat-fault.so', root / 'preload-capability.marker'
    if shim.exists() and marker.exists():
        env = dict(os.environ, LD_PRELOAD=str(shim), RUT_TEST_LINKAT_FAIL_AT='1')
        for command, identity, value in (
            ('set-consumer-enabled', consumers[0]['id'], 'false'),
            ('set-credential-enabled', credentials[0]['id'], 'false'),
            ('set-consumer-groups', consumers[0]['id'], groups)):
            update(command, identity, value, env=env)
    for command in ('set-consumer-enabled', 'set-credential-enabled', 'set-consumer-groups'):
        for args in ([], ['a'], ['a', 'b'], ['a', 'b', 'c'], ['a', 'b', 'c', 'd', 'e']):
            assert run(tool, command, *args).returncode == 2
    assert not list(work.glob('.rut-consumers-*'))


def main(tool):
    assert run(tool, '--help').returncode == 0
    for args in [[], ['init'], ['apply'], ['inspect'], ['validate'], ['plan'],
                 ['plan', 'a'], ['plan', 'a', 'b', 'c'], ['init', 'a', 'b'],
                 ['apply', 'a', 'b', 'c', 'd'], ['diff'], ['diff', 'a'],
                 ['diff', 'a', 'b', 'c'], ['unknown']]:
        result = run(tool, *args)
        assert result.returncode == 2 and not result.stdout
    with tempfile.TemporaryDirectory(prefix='rut-consumers-cli-') as directory:
        root = Path(directory)
        test_deployment_policy(tool, root)
        test_apply_checked(tool, root)
        test_prune_credentials(tool, root)
        test_targeted_registry_commands(tool, root)
        test_generated_keys(tool, root)
        test_time_window_metadata_survives_cli(tool, root)
        test_hash_keys(tool, root)
        test_generated_key_verifier(tool, root)
        test_provision_key_verifier(tool, root)
        test_targeted_metadata(tool, root)
        test_rotated_key_verifier(tool, root)
        test_credential_groups_preserve_and_reject_parent_removal(tool, root)
        test_snapshot_diff(tool, root)
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
