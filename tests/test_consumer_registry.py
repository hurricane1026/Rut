#!/usr/bin/env python3
"""Snapshot lifecycle and strict header authentication through relocated artifacts."""
import argparse
from contextlib import contextmanager
from auth_h2_fixture import request as h2_request
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def consumer(name,enabled=True,groups=None):
    return dict(id=name,enabled=enabled,groups=groups or [])


def credential(name,owner,method,secret,enabled=True):
    return dict(id=name,consumerId=owner,method=method,secret=secret,enabled=enabled)


@contextmanager
def gateway(args,config,root,invalid=False):
    root.mkdir()
    with socket.socket() as probe:
        probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
    source=root/'registry.rut'
    source.write_text(Path(args.source).read_text().replace('listen :8080',f'listen :{port}'))
    log=root/'gateway.log'
    with log.open('w') as output:
        process=subprocess.Popen([args.server,str(source),'--backend',args.backend,'--no-pin',
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
        for secret in ['alice-current','alice-old','alice:password','custom-key']:
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


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--server',required=True)
    parser.add_argument('--source',required=True)
    parser.add_argument('--backend',required=True)
    args=parser.parse_args()
    initial=dict(version=1,consumers=[consumer('alice',groups=['staff'])],credentials=[
        credential('old','alice','bearer','alice-old'),
        credential('current','alice','bearer','alice-current'),
        credential('password','alice','basic','alice:password'),
        credential('key','alice','header','custom-key')])
    with tempfile.TemporaryDirectory(prefix='rut-consumers-') as tmp:
        root=Path(tmp)
        with gateway(args,initial,root/'initial') as first:
            for value,expected in [('',401),('Bearer alice-current',200),('Bearer alice-old',200),
                                   ('Bearer wrong',401),('Bearer alice-current ',200)]:
                fields=f'Authorization: {value}\r\n' if value else ''
                status,body=request(first,'/private',fields)
                assert status==expected,(value,status)
                if status==200:assert body==b'alice'
            assert request(first,'/private','Authorization: Bearer alice-current\r\nAuthorization: Bearer alice-current\r\n')[0]==401
            assert request(first,'/staff','Authorization: Bearer alice-current\r\n')[0]==204
            assert request(first,'/basic','Authorization: Basic YWxpY2U6cGFzc3dvcmQ=\r\n')[0]==204
            assert request(first,'/key','X-API-Key: custom-key\r\n')[0]==204
            assert request(first,'/key','X-API-Key: custom-key\r\nX-API-Key: custom-key\r\n')[0]==401
            assert h2_request(first,'/private',[('authorization','Bearer alice-current')])==(200,b'alice')
            assert h2_request(first,'/private',[('authorization','Bearer alice-current'),('authorization','Bearer alice-current')])[0]==401
            assert h2_request(first,'/key',[('x-api-key','custom-key'),('x-api-key','custom-key')])[0]==401
            updated=json.loads(json.dumps(initial));updated['credentials'][0]['enabled']=False
            updated['consumers'][0]['groups']=[]
            updated['consumers'].append(consumer('bob'))
            updated['credentials'].append(credential('bob','bob','bearer','bob-key'))
            with gateway(args,updated,root/'updated') as second:
                assert request(second,'/private','Authorization: Bearer alice-old\r\n')[0]==401
                assert request(second,'/staff','Authorization: Bearer alice-current\r\n')[0]==403
                assert request(second,'/private','Authorization: Bearer bob-key\r\n')==(200,b'bob')
                # Already published programs retain their independently owned snapshot.
                assert request(first,'/staff','Authorization: Bearer alice-old\r\n')[0]==204
            invalid=json.loads(json.dumps(initial))
            invalid['credentials'].append(credential('ambiguous','alice','bearer','alice-current'))
            with gateway(args,invalid,root/'invalid',invalid=True):pass
            assert request(first,'/private','Authorization: Bearer alice-current\r\n')[0]==200
        disabled=json.loads(json.dumps(initial));disabled['consumers'][0]['enabled']=False
        with gateway(args,disabled,root/'disabled') as port:
            assert request(port,'/private','Authorization: Bearer alice-current\r\n')[0]==401
    print('PASS: Consumer creation, disable, credential retirement, groups, snapshot isolation and invalid update')


if __name__=='__main__':main()
