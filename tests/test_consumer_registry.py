#!/usr/bin/env python3
"""Snapshot lifecycle and strict header authentication through relocated artifacts."""
import argparse
from contextlib import contextmanager
from auth_h2_fixture import request as h2_request
import http.client
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def consumer(name,enabled=True,groups=None):
    return dict(id=name,enabled=enabled,groups=groups or [])


def credential(name,owner,method,secret,enabled=True,groups=None):
    record = dict(id=name,consumerId=owner,method=method,secret=secret,enabled=enabled)
    if groups is not None:
        record['groups'] = groups
    return record


@contextmanager
def gateway(args,config,root,invalid=False,sensitive=()):
    root.mkdir()
    with socket.socket() as probe:
        probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
    source=root/'registry.rut'
    source.write_text(Path(args.source).read_text().replace('listen :8080',f'listen :{port}'))
    log=root/'gateway.log'
    with log.open('w') as output:
        process=subprocess.Popen([args.server,str(source),'--backend',args.backend,'--opt',args.opt,'--no-pin',
                                  '--shards','2','--drain','0','--max-connections-per-shard','128'],
                                 env=dict(os.environ,AUTH_REGISTRY=json.dumps(config)),
                                 stdout=output,stderr=subprocess.STDOUT)
    try:
        deadline=time.monotonic()+30
        while True:
            if process.poll() is not None:
                data=log.read_text()
                if invalid:
                    assert 'invalid Consumer registry snapshot' in data,data
                    yield None
                    return
                if args.backend=='io_uring' and 'io_uring is unavailable' in data:
                    raise SystemExit(77)
                raise AssertionError(data)
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.1):break
            except OSError:
                assert time.monotonic()<deadline,log.read_text()
                time.sleep(.025)
        assert not invalid,'bad snapshot was accepted'
        source.unlink()
        yield port
    finally:
        process.terminate()
        try:process.wait(5)
        except subprocess.TimeoutExpired:process.kill();process.wait()
        for secret in ['alice-current','alice-old','alice:password','custom-key','window-key',*sensitive]:
            assert secret not in log.read_text(),log.read_text()


def request(port,path,header):
    body=b'api_key=custom-key'
    wire=(f'GET {path}?api_key=custom-key HTTP/1.1\r\nHost: local\r\nConnection: close\r\n'+
          'X-Consumer-ID: alice\r\nX-Groups: staff\r\n'+header+
          f'Content-Length: {len(body)}\r\n\r\n').encode()+body
    with socket.create_connection(('127.0.0.1',port),timeout=4) as connection:
        connection.sendall(wire);data=b''
        while True:
            chunk=connection.recv(8192)
            if not chunk:break
            data+=chunk
    head,body=data.split(b'\r\n\r\n',1)
    return int(head.split(b' ',2)[1]),body


def administer(args, root, name, config, previous=None):
    if not args.admin:
        return config
    base = previous or root / 'empty.json'
    if previous is None:
        subprocess.run([args.admin, 'init', str(base)], check=True, capture_output=True)
    patch = root / (name + '-changes.json')
    patch.write_text(json.dumps(dict(consumers=config['consumers'], credentials=config['credentials'],
                                    removeConsumers=[], removeCredentials=[])))
    patch.chmod(0o600)
    target = root / (name + '.json')
    subprocess.run([args.admin, 'apply', str(base), str(patch), str(target)],
                   check=True, capture_output=True)
    return json.loads(target.read_text())


def provision_profiles(args, root):
    base = root / 'provision-empty.json'
    result = subprocess.run([args.admin, 'init', str(base)], capture_output=True, timeout=10)
    assert result.returncode == 0 and not result.stdout and not result.stderr
    owner = dict(id='profile-owner', enabled=True, groups=['staff', 'readers', 'writers'])
    keys = {}
    policies = [('reader', dict(groups=['readers'], notBefore=1, expiresAt=9223372036854775807)),
                ('empty', dict(groups=[])), ('inherited', {}),
                ('future', dict(notBefore=9223372036854775807)),
                ('expired', dict(expiresAt=1)), ('disabled', dict(enabled=False)),
                ('header', dict(method='header', groups=[])),
                ('paused', dict(consumerId='profile-paused'))]
    for index, (name, fields) in enumerate(policies):
        record = dict(id='profile-' + name, consumerId=owner['id'], method='bearer', enabled=True)
        record.update(fields)
        profile = dict(credential=record)
        if index == 0:
            profile['consumer'] = owner
        if name == 'paused':
            profile['consumer'] = dict(id='profile-paused', enabled=False, groups=[])
        profile_path = root / f'{name}-profile.json'
        profile_path.write_text(json.dumps(profile))
        profile_path.chmod(0o600)
        output, key = root / f'{name}-provisioned.json', root / f'{name}-private-key'
        before = base.read_bytes(), profile_path.read_bytes()
        result = subprocess.run([args.admin, 'provision-key-verifier', str(base), str(profile_path),
                                 str(output), str(key)], capture_output=True, timeout=10)
        assert result.returncode == 0 and not result.stdout and not result.stderr, result
        assert (base.read_bytes(), profile_path.read_bytes()) == before
        keys[name] = key.read_text()
        base = output
    configuration = json.loads(base.read_bytes())
    with gateway(args, configuration, root / 'provisioned-gateway',
                 sensitive=tuple(keys.values())) as port:
        for name, path, expected in (
            ('reader', '/private', 200), ('reader', '/read', 200),
            ('reader', '/staff', 403), ('reader', '/write', 403),
            ('empty', '/private', 200), ('empty', '/read', 403),
            ('inherited', '/staff', 204), ('inherited', '/write', 200),
            ('future', '/private', 401), ('expired', '/private', 401),
            ('disabled', '/private', 401), ('paused', '/private', 401), ('header', '/key', 204)):
            field = 'X-API-Key' if name == 'header' else 'Authorization'
            presented = keys[name] if name == 'header' else 'Bearer ' + keys[name]
            assert request(port, path, f'{field}: {presented}\r\n')[0] == expected
            assert h2_request(port, path, [(field.lower(), presented)])[0] == expected


def targeted_lifecycle(args, root):
    original = dict(version=1, consumers=[consumer('state-owner', groups=['staff', 'readers'])],
        credentials=[
            credential('state-inherit', 'state-owner', 'bearer', 'state-inherit-key'),
            credential('state-reader', 'state-owner', 'bearer', 'state-reader-key', groups=['readers']),
            credential('state-empty', 'state-owner', 'bearer', 'state-empty-key', groups=[]),
            credential('state-header', 'state-owner', 'header', 'state-header-key'),
            credential('state-basic', 'state-owner', 'basic', 'state-user:state-password'),
            dict(credential('state-expired', 'state-owner', 'bearer', 'state-expired-key', False), expiresAt=1)])
    source = root / 'state-source.json'
    source.write_text(json.dumps(original))
    source.chmod(0o600)
    sensitive = tuple(record['secret'] for record in original['credentials'])
    counter = 0
    def change(command, identity, value, base=source):
        nonlocal counter
        counter += 1
        output = root / f'state-output-{counter}.json'
        before = base.read_bytes()
        result = subprocess.run([args.admin, command, str(base), identity, str(value), str(output)],
                                capture_output=True, timeout=10)
        assert result.returncode == 0 and not result.stdout and not result.stderr, result
        assert base.read_bytes() == before
        return output
    def check(port, path, value, status, header='Authorization'):
        assert request(port, path, f'{header}: {value}\r\n')[0] == status
        assert h2_request(port, path, [(header.lower(), value)])[0] == status
    with gateway(args, original, root / 'state-original', sensitive=sensitive) as pinned:
        check(pinned, '/staff', 'Bearer state-inherit-key', 204)
        disabled = change('set-consumer-enabled', 'state-owner', 'false')
        with gateway(args, json.loads(disabled.read_bytes()), root / 'state-disabled', sensitive=sensitive) as port:
            for key in ('state-inherit-key', 'state-reader-key', 'state-empty-key'):
                check(port, '/private', 'Bearer ' + key, 401)
            check(port, '/key', 'state-header-key', 401, 'X-API-Key')
        check(pinned, '/private', 'Bearer state-inherit-key', 200)
        enabled = change('set-consumer-enabled', 'state-owner', 'true', disabled)
        retired = change('set-credential-enabled', 'state-inherit', 'false', enabled)
        with gateway(args, json.loads(retired.read_bytes()), root / 'state-retired', sensitive=sensitive) as port:
            check(port, '/private', 'Bearer state-inherit-key', 401)
            check(port, '/read', 'Bearer state-reader-key', 200)
        restored = change('set-credential-enabled', 'state-inherit', 'true', retired)
        restored = change('set-credential-enabled', 'state-expired', 'true', restored)
        groups = root / 'state-groups.json'
        groups.write_text(json.dumps(['staff', 'readers', 'writers']))
        groups.chmod(0o600)
        regrouped = change('set-consumer-groups', 'state-owner', groups, restored)
        with gateway(args, json.loads(regrouped.read_bytes()), root / 'state-regrouped', sensitive=sensitive) as port:
            check(port, '/write', 'Bearer state-inherit-key', 200)
            check(port, '/write', 'Bearer state-reader-key', 403)
            check(port, '/write', 'Bearer state-empty-key', 403)
            check(port, '/private', 'Bearer state-expired-key', 401)
        check(pinned, '/write', 'Bearer state-inherit-key', 403)
        groups.write_text(json.dumps(['readers']))
        narrowed = change('set-consumer-groups', 'state-owner', groups, regrouped)
        with gateway(args, json.loads(narrowed.read_bytes()), root / 'state-narrowed', sensitive=sensitive) as port:
            check(port, '/staff', 'Bearer state-inherit-key', 403)
            check(port, '/read', 'Bearer state-inherit-key', 200)
            check(port, '/read', 'Bearer state-reader-key', 200)
        check(pinned, '/staff', 'Bearer state-inherit-key', 204)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--server',required=True)
    parser.add_argument('--source',required=True)
    parser.add_argument('--backend',required=True)
    parser.add_argument('--opt',choices=('0','2'),default='2')
    parser.add_argument('--admin')
    args=parser.parse_args()
    initial=dict(version=1,consumers=[consumer('alice',groups=['staff','readers','writers'])],credentials=[
        credential('old','alice','bearer','alice-old'),
        credential('current','alice','bearer','alice-current'),
        credential('read-only','alice','bearer','alice-read',groups=['readers']),
        credential('write-only','alice','bearer','alice-write',groups=['writers']),
        credential('password','alice','basic','alice:password'),
        credential('key','alice','header','custom-key')])
    with tempfile.TemporaryDirectory(prefix='rut-consumers-') as tmp:
        root=Path(tmp)
        initial=administer(args,root,'initial-snapshot',initial)
        generated = {}
        if args.admin:
            targeted_lifecycle(args, root)
            provision_profiles(args, root)
            base = root / 'initial-snapshot.json'
            for credential_id, method in [('generated-bearer-v1', 'bearer'),
                                          ('generated-bearer-v2', 'bearer'),
                                          ('generated-header-v1', 'header')]:
                output = root / f'{credential_id}.json'
                result = subprocess.run([args.admin, 'generate-key', str(base), 'alice',
                                         credential_id, method, str(output)],
                                        capture_output=True, timeout=10)
                assert result.returncode == 0 and not result.stdout and not result.stderr, result
                assert output.stat().st_mode & 0o777 == 0o600
                base = output
                snapshot = json.loads(output.read_bytes())
                generated[credential_id] = next(item['secret'] for item in snapshot['credentials']
                                                 if item['id'] == credential_id)
                initial = snapshot
            assert generated['generated-bearer-v1'] != generated['generated-bearer-v2']
            paired_snapshot = root / 'paired-bearer.snapshot.json'
            paired_key = root / 'paired-bearer.key'
            paired_result = subprocess.run(
                [args.admin, 'generate-key-verifier', str(root / 'initial-snapshot.json'),
                 'alice', 'paired-bearer-v1', 'bearer', str(paired_snapshot), str(paired_key)],
                capture_output=True, timeout=10)
            assert paired_result.returncode == 0 and not paired_result.stdout and not paired_result.stderr
            bearer_bytes = paired_key.read_bytes()
            assert len(bearer_bytes) == 64 and all(byte in b'0123456789abcdef' for byte in bearer_bytes)
            assert paired_key.stat().st_mode & 0o777 == 0o600
            paired_config = json.loads(paired_snapshot.read_bytes())
            paired_record = next(item for item in paired_config['credentials']
                                 if item['id'] == 'paired-bearer-v1')
            assert 'secret' not in paired_record
            bearer_verifier = hashlib.sha256(bearer_bytes).hexdigest()
            assert paired_record['secretSha256'] == bearer_verifier

            header_snapshot = root / 'paired-header.snapshot.json'
            header_key = root / 'paired-header.key'
            header_result = subprocess.run(
                [args.admin, 'generate-key-verifier', str(paired_snapshot), 'alice',
                 'paired-header-v1', 'header', str(header_snapshot), str(header_key)],
                capture_output=True, timeout=10)
            assert header_result.returncode == 0 and not header_result.stdout and not header_result.stderr
            header_bytes = header_key.read_bytes()
            assert len(header_bytes) == 64 and all(byte in b'0123456789abcdef' for byte in header_bytes)
            assert header_key.stat().st_mode & 0o777 == 0o600
            paired_config = json.loads(header_snapshot.read_bytes())
            header_record = next(item for item in paired_config['credentials']
                                 if item['id'] == 'paired-header-v1')
            assert 'secret' not in header_record
            header_verifier = hashlib.sha256(header_bytes).hexdigest()
            assert header_record['secretSha256'] == header_verifier
            compiler = Path(args.server).with_name('rut-compile')
            artifact = subprocess.run([str(compiler), args.source, args.opt],
                                      env=dict(os.environ, AUTH_REGISTRY=json.dumps(paired_config)),
                                      capture_output=True, timeout=90)
            assert artifact.returncode == 0, artifact.stderr.decode(errors='replace')
            for raw_key in (bearer_bytes, header_bytes):
                assert raw_key not in artifact.stdout + artifact.stderr
            with gateway(args, paired_config, root / 'paired-keys',
                         sensitive=(bearer_bytes.decode(), header_bytes.decode())) as paired_port:
                assert request(paired_port, '/private',
                               f'Authorization: Bearer {bearer_bytes.decode()}\r\n') == (200, b'alice')
                assert request(paired_port, '/private',
                               f'Authorization: Bearer {bearer_verifier}\r\n')[0] == 401
                assert request(paired_port, '/key',
                               f'X-API-Key: {header_bytes.decode()}\r\n')[0] == 204
                assert request(paired_port, '/key',
                               f'X-API-Key: {header_verifier}\r\n')[0] == 401
                assert h2_request(paired_port, '/private',
                                  [('authorization', f'Bearer {bearer_bytes.decode()}')]) == (200, b'alice')
                assert h2_request(paired_port, '/private',
                                  [('authorization', f'Bearer {bearer_verifier}')])[0] == 401
                assert h2_request(paired_port, '/key',
                                  [('x-api-key', header_bytes.decode())])[0] == 204
                assert h2_request(paired_port, '/key',
                                  [('x-api-key', header_verifier)])[0] == 401
            # Rotate both existing hashed methods, retaining a least-privilege subset.
            bearer_record = next(item for item in paired_config['credentials']
                                 if item['id'] == 'paired-bearer-v1')
            bearer_record.update(groups=['readers'], notBefore=1, expiresAt=int(time.time()) + 600)
            rotation_input = root / 'rotation-input.json'
            rotation_input.write_text(json.dumps(paired_config))
            rotation_input.chmod(0o600)
            rotated_keys = {}
            for old_id in ('paired-bearer-v1', 'paired-header-v1'):
                rotation_output = root / f'{old_id}-rotated.json'
                rotation_key = root / f'{old_id}-rotated.key'
                before = rotation_input.read_bytes()
                result = subprocess.run([args.admin, 'rotate-key-verifier', str(rotation_input),
                                         old_id, old_id + '-rotated', str(rotation_output), str(rotation_key)],
                                        capture_output=True, timeout=10)
                assert result.returncode == 0 and not result.stdout and not result.stderr, result
                assert rotation_input.read_bytes() == before
                rotated_keys[old_id] = rotation_key.read_text()
                rotation_input = rotation_output
            rotated = json.loads(rotation_input.read_bytes())
            with gateway(args, rotated, root / 'rotated-keys',
                         sensitive=(bearer_bytes.decode(), header_bytes.decode(),
                                    *rotated_keys.values())) as rotation_port:
                for path, field, old, new, expected in (
                    ('/private', 'Authorization', 'Bearer ' + bearer_bytes.decode(),
                     'Bearer ' + rotated_keys['paired-bearer-v1'], 200),
                    ('/key', 'X-API-Key', header_bytes.decode(), rotated_keys['paired-header-v1'], 204)):
                    assert request(rotation_port, path, f'{field}: {old}\r\n')[0] == 401
                    assert h2_request(rotation_port, path, [(field.lower(), old)])[0] == 401
                    assert request(rotation_port, path, f'{field}: {new}\r\n')[0] == expected
                    assert h2_request(rotation_port, path, [(field.lower(), new)])[0] == expected
                authorization = 'Bearer ' + rotated_keys['paired-bearer-v1']
                for path, expected in (('/read', 200), ('/staff', 403), ('/write', 403)):
                    assert request(rotation_port, path, f'Authorization: {authorization}\r\n')[0] == expected
                    assert h2_request(rotation_port, path, [('authorization', authorization)])[0] == expected
        if args.admin and generated:
            activation = max(1, int(time.time()) - 10)
            expiry = int(time.time()) + 600
            raw_profile = dict(version=1, consumers=[consumer('alice', groups=['staff'])],
                credentials=[
                    dict(id='hashed-bearer', consumerId='alice', method='bearer',
                         secret=generated['generated-bearer-v1'], enabled=True,
                         notBefore=activation, expiresAt=expiry),
                    dict(id='hashed-header', consumerId='alice', method='header',
                         secret=generated['generated-header-v1'], enabled=True,
                         notBefore=activation, expiresAt=expiry),
                ])
            raw_path = root / 'raw-key-profile.json'
            raw_path.write_text(json.dumps(raw_profile))
            raw_path.chmod(0o600)
            hashed_path = root / 'hashed-key-profile.json'
            converted = subprocess.run([args.admin, 'hash-keys', str(raw_path), str(hashed_path)],
                                       capture_output=True, timeout=10)
            assert converted.returncode == 0 and not converted.stdout and not converted.stderr, converted
            hashed_profile = json.loads(hashed_path.read_bytes())
            assert raw_path.read_bytes() == json.dumps(raw_profile).encode()
            assert hashed_path.stat().st_mode & 0o777 == 0o600
            digest_by_id = {item['id']: item['secretSha256']
                            for item in hashed_profile['credentials']}
            assert all('secret' not in item for item in hashed_profile['credentials'])
            assert all(item['notBefore'] == activation and item['expiresAt'] == expiry
                       for item in hashed_profile['credentials'])
            compiler = Path(args.server).with_name('rut-compile')
            artifact = subprocess.run([str(compiler), args.source, args.opt],
                                      env=dict(os.environ, AUTH_REGISTRY=json.dumps(hashed_profile)),
                                      capture_output=True, timeout=90)
            assert artifact.returncode == 0, artifact.stderr.decode(errors='replace')
            for original_key in (generated['generated-bearer-v1'], generated['generated-header-v1']):
                assert original_key.encode() not in artifact.stdout + artifact.stderr
            with gateway(args, hashed_profile, root / 'hashed-profile') as hashed_port:
                bearer = generated['generated-bearer-v1']
                header = generated['generated-header-v1']
                assert request(hashed_port, '/private', f'Authorization: Bearer {bearer}\r\n') == (200, b'alice')
                assert request(hashed_port, '/private', f'Authorization: Bearer {digest_by_id["hashed-bearer"]}\r\n')[0] == 401
                assert request(hashed_port, '/key', f'X-API-Key: {header}\r\n')[0] == 204
                assert request(hashed_port, '/key', f'X-API-Key: {digest_by_id["hashed-header"]}\r\n')[0] == 401
                assert h2_request(hashed_port, '/private', [('authorization', f'Bearer {bearer}')]) == (200, b'alice')
                assert h2_request(hashed_port, '/private', [('authorization', f'Bearer {digest_by_id["hashed-bearer"]}')])[0] == 401
                assert h2_request(hashed_port, '/key', [('x-api-key', header)])[0] == 204
                assert h2_request(hashed_port, '/key', [('x-api-key', digest_by_id['hashed-header'])])[0] == 401
        with gateway(args,initial,root/'initial') as first:
            for value,expected in [('',401),('Bearer alice-current',200),('Bearer alice-old',200),
                                   ('Bearer wrong',401),('Bearer alice-current ',200)]:
                fields=f'Authorization: {value}\r\n' if value else ''
                status,body=request(first,'/private',fields)
                assert status==expected,(value,status)
                if status==200:assert body==b'alice'
            assert request(first,'/private','Authorization: Bearer alice-current\r\nAuthorization: Bearer alice-current\r\n')[0]==401
            assert request(first,'/staff','Authorization: Bearer alice-current\r\n')[0]==204
            assert request(first,'/read','Authorization: Bearer alice-read\r\n')==(200,b'alice')
            assert request(first,'/write','Authorization: Bearer alice-read\r\nX-Groups: writers\r\n')[0]==403
            assert request(first,'/write','Authorization: Bearer alice-write\r\n')==(200,b'alice')
            assert request(first,'/read','Authorization: Bearer alice-write\r\n')[0]==403
            assert request(first,'/basic','Authorization: Basic YWxpY2U6cGFzc3dvcmQ=\r\n')[0]==204
            assert request(first,'/key','X-API-Key: custom-key\r\n')[0]==204
            assert request(first,'/key','X-API-Key: custom-key\r\nX-API-Key: custom-key\r\n')[0]==401
            if generated:
                assert request(first,'/private',f'Authorization: Bearer {generated["generated-bearer-v1"]}\r\n')==(200,b'alice')
                assert request(first,'/private',f'Authorization: Bearer {generated["generated-bearer-v2"]}\r\n')==(200,b'alice')
                assert request(first,'/key',f'X-API-Key: {generated["generated-header-v1"]}\r\n')[0]==204
                assert h2_request(first,'/private',[('authorization',f'Bearer {generated["generated-bearer-v1"]}')])==(200,b'alice')
                assert h2_request(first,'/key',[('x-api-key',generated["generated-header-v1"])])[0]==204
            assert h2_request(first,'/private',[('authorization','Bearer alice-current')])==(200,b'alice')
            assert h2_request(first,'/read',[('authorization','Bearer alice-read')])==(200,b'alice')
            assert h2_request(first,'/write',[('authorization','Bearer alice-read'),('x-groups','writers')])[0]==403
            assert h2_request(first,'/write',[('authorization','Bearer alice-write')])==(200,b'alice')
            assert h2_request(first,'/read',[('authorization','Bearer alice-write')])[0]==403
            assert h2_request(first,'/private',[('authorization','Bearer alice-current'),('authorization','Bearer alice-current')])[0]==401
            assert h2_request(first,'/key',[('x-api-key','custom-key'),('x-api-key','custom-key')])[0]==401
            updated=json.loads(json.dumps(initial));updated['credentials'][0]['enabled']=False
            if generated:
                next(item for item in updated['credentials'] if item['id']=='generated-bearer-v1')['enabled']=False
            updated['consumers'][0]['groups']=['readers']
            next(item for item in updated['credentials'] if item['id']=='write-only')['groups']=[]
            updated['consumers'].append(consumer('bob'))
            updated['credentials'].append(credential('bob','bob','bearer','bob-key'))
            updated=administer(args,root,'updated-snapshot',updated,root/'initial-snapshot.json')
            with gateway(args,updated,root/'updated') as second:
                assert request(second,'/private','Authorization: Bearer alice-old\r\n')[0]==401
                if generated:
                    assert request(second,'/private',f'Authorization: Bearer {generated["generated-bearer-v1"]}\r\n')[0]==401
                    assert request(second,'/private',f'Authorization: Bearer {generated["generated-bearer-v2"]}\r\n')==(200,b'alice')
                assert request(second,'/staff','Authorization: Bearer alice-current\r\n')[0]==403
                assert request(second,'/read','Authorization: Bearer alice-read\r\n')==(200,b'alice')
                assert request(second,'/write','Authorization: Bearer alice-write\r\n')[0]==403
                assert request(second,'/private','Authorization: Bearer bob-key\r\n')==(200,b'bob')
                # Already published programs retain their independently owned snapshot.
                assert request(first,'/staff','Authorization: Bearer alice-old\r\n')[0]==204
                assert request(first,'/write','Authorization: Bearer alice-write\r\n')==(200,b'alice')
                if generated:
                    assert request(first,'/private',f'Authorization: Bearer {generated["generated-bearer-v1"]}\r\n')==(200,b'alice')
            invalid=json.loads(json.dumps(initial))
            invalid['credentials'].append(credential('ambiguous','alice','bearer','alice-current'))
            with gateway(args,invalid,root/'invalid',invalid=True):pass
            assert request(first,'/private','Authorization: Bearer alice-current\r\n')[0]==200
        disabled=json.loads(json.dumps(initial));disabled['consumers'][0]['enabled']=False
        disabled=administer(args,root,'disabled-snapshot',disabled,root/'initial-snapshot.json')
        with gateway(args,disabled,root/'disabled') as port:
            assert request(port,'/private','Authorization: Bearer alice-current\r\n')[0]==401
        # Keep several seconds between compile/startup and activation so slow
        # JIT hosts still observe the pre-activation denial.
        activation = int(time.time()) + 40
        expiry = activation + 10
        timed = dict(version=1, consumers=[consumer('alice',groups=['staff'])],
                     credentials=[dict(id='window', consumerId='alice', method='bearer',
                                       secret='window-key', enabled=True,
                                       notBefore=activation, expiresAt=expiry, groups=[])])
        timed_key = 'window-key'
        if args.admin:
            timed_source = root / 'timed-rotation-input.json'
            timed_source.write_text(json.dumps(timed))
            timed_source.chmod(0o600)
            timed_output, timed_key_output = root / 'timed-rotation.json', root / 'timed-rotation.key'
            result = subprocess.run([args.admin, 'rotate-key-verifier', str(timed_source),
                                     'window', 'window-rotated', str(timed_output), str(timed_key_output)],
                                    capture_output=True, timeout=10)
            assert result.returncode == 0 and not result.stdout and not result.stderr, result
            timed = json.loads(timed_output.read_bytes())
            timed_key = timed_key_output.read_text()
        with gateway(args,timed,root/'timed',sensitive=(timed_key,)) as port:
            connection=http.client.HTTPConnection('127.0.0.1',port,timeout=8)
            h2_headers=[('authorization','Bearer ' + timed_key)]
            persistent_socket=None
            def persistent_status():
                nonlocal persistent_socket
                connection.request('GET','/private',headers={'Authorization':'Bearer ' + timed_key})
                response=connection.getresponse()
                status,body=response.status,response.read()
                if persistent_socket is None:
                    persistent_socket=connection.sock
                    assert persistent_socket is not None, 'HTTP/1 client closed its connection after the first request'
                else:
                    assert connection.sock is persistent_socket, 'HTTP/1 client reconnected between window transitions'
                return status,body
            assert persistent_status()[0]==401
            assert h2_request(port,'/private',h2_headers)[0]==401
            while True:
                status,body=persistent_status()
                if status==200:
                    assert body==b'alice' and time.time()>=activation
                    break
                assert status==401 and time.time()<expiry,(status,body,time.time())
                time.sleep(.25)
            assert h2_request(port,'/private',h2_headers)==(200,b'alice')
            assert request(port, '/staff', f'Authorization: Bearer {timed_key}\r\n')[0] == 403
            assert h2_request(port, '/staff', h2_headers)[0] == 403
            if args.admin:
                assert request(port, '/private', 'Authorization: Bearer window-key\r\n')[0] == 401
                assert h2_request(port, '/private', [('authorization', 'Bearer window-key')])[0] == 401
            while True:
                status,body=persistent_status()
                if status==401:
                    assert time.time()>=expiry,(status,body,time.time())
                    break
                assert status==200 and body==b'alice',(status,body)
                assert time.time()<expiry+5,'credential did not expire within the bounded grace period'
                time.sleep(.25)
            assert h2_request(port,'/private',h2_headers)[0]==401
            connection.close()
    print('PASS: Consumer creation, disable, credential retirement, groups, snapshot isolation and invalid update')


if __name__=='__main__':main()
