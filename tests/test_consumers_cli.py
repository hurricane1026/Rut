#!/usr/bin/env python3
"""Consumer administration, atomic rejection and secret-safe filesystem policy."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
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


def main(tool):
    assert run(tool, '--help').returncode == 0
    for args in [[], ['init'], ['apply'], ['inspect'], ['validate'], ['plan'],
                 ['plan', 'a'], ['plan', 'a', 'b', 'c'], ['init', 'a', 'b'],
                 ['apply', 'a', 'b', 'c', 'd'], ['unknown']]:
        result = run(tool, *args)
        assert result.returncode == 2 and not result.stdout
    with tempfile.TemporaryDirectory(prefix='rut-consumers-cli-') as directory:
        root = Path(directory)
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
        before = {p.name: p.read_bytes() for p in root.iterdir()}
        planned = run(tool, 'plan', initial, patch)
        assert planned.returncode == 0 and not planned.stderr
        assert planned.stdout == inspected.stdout
        assert b'private-key' not in planned.stdout + planned.stderr
        assert {p.name: p.read_bytes() for p in root.iterdir()} == before
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
