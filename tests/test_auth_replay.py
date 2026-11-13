#!/usr/bin/env python3
"""Independent atomic RESP2 peer and signed HTTP requests, including restart/replay."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
from email.utils import formatdate
from auth_h2_fixture import request as h2_request
import hmac
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import traceback
from test_redis_commands import assert_ack_boundary

KEY = 'standard-webhook-fixture-0123456789'
SIGNED = False
SIGNED_TIME = int(time.time())


class Store:
    def __init__(self, certificates, tls, durable=False):
        self.lock = threading.Lock()
        self.claims = {}
        self.mode = 'normal'
        self.commands = []
        self.errors = []
        self.workers = []
        self.stopping = threading.Event()
        self.durable = durable
        self.barrier_entered = threading.Event()
        self.release_barrier = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(64)
        self.listener.settimeout(.1)
        self.port = self.listener.getsockname()[1]
        self.context = None
        if tls:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(str(certificates / 'localhost_cert.pem'),
                                         str(certificates / 'localhost_key.pem'))
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stopping.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            worker = threading.Thread(target=self.serve, args=(connection,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def serve(self, connection):
        try:
            connection.settimeout(3)
            if self.context:
                connection = self.context.wrap_socket(connection, server_side=True)
            with connection, connection.makefile('rb') as stream:
                authenticated, selected = False, False
                while True:
                    line = stream.readline(64)
                    if not line:
                        return
                    assert line.startswith(b'*'), line
                    count = int(line[1:])
                    assert 1 <= count <= 6
                    args = []
                    for _ in range(count):
                        line = stream.readline(64)
                        assert line.startswith(b'$')
                        length = int(line[1:])
                        assert 0 <= length <= 8192
                        args.append(stream.read(length))
                        assert stream.read(2) == b'\r\n'
                    with self.lock:
                        mode = self.mode
                        self.commands.append(args)
                    if args[0] == b'AUTH':
                        assert args == [b'AUTH', b'gateway', b'service-password']
                        authenticated = mode != 'auth-error'
                        reply = b'+OK\r\n' if authenticated else b'-WRONGPASS\r\n'
                    elif args[0] == b'SELECT':
                        assert args == [b'SELECT', b'1']
                        selected = authenticated and mode != 'select-error'
                        reply = b'+OK\r\n' if selected else b'-ERR\r\n'
                    elif args[0] == b'SET':
                        assert authenticated and selected
                        assert args[2:] == [b'claimed', b'NX', b'EX', b'601'], args
                        assert args[1].startswith(b'replay:billing:')
                        assert len(args[1].split(b':')[-1]) == 64
                        with self.lock:
                            duplicate = self.claims.get(args[1], 0) > time.monotonic()
                            if not duplicate and mode != 'set-error':
                                self.claims[args[1]] = time.monotonic() + 601
                        reply = b'$-1\r\n' if duplicate else b'+OK\r\n'
                        if mode == 'set-error': reply = b'-ERR full\r\n'
                        if mode == 'set-wrong': reply = b':1\r\n'
                        if mode == 'set-trailing': reply += b'+OK\r\n'
                        if mode == 'set-eof': return
                        if mode == 'set-timeout':
                            self.stopping.wait(1.4)
                            return
                    elif args[0] == b'WAITAOF':
                        assert self.durable and authenticated and selected
                        assert args == [b'WAITAOF', b'1', b'0', b'500']
                        assert_ack_boundary(connection, stream, 'cleanup preceded AOF confirmation')
                        reply = b'*2\r\n:1\r\n:0\r\n'
                        if mode == 'aof-error': reply = b'-ERR AOF disabled\r\n'
                        if mode == 'aof-timeout': reply = b'*2\r\n:0\r\n:0\r\n'
                        if mode == 'aof-negative': reply = b'*2\r\n:1\r\n:-1\r\n'
                        if mode == 'aof-local': reply = b'*2\r\n:2\r\n:0\r\n'
                        if mode == 'aof-type': reply = b'*2\r\n$1\r\n1\r\n:0\r\n'
                        if mode == 'aof-arity': reply = b'*1\r\n:1\r\n'
                        if mode == 'aof-nested': reply = b'*2\r\n*1\r\n:1\r\n:0\r\n'
                        if mode == 'aof-overflow': reply = b'*2\r\n:1\r\n:9223372036854775808\r\n'
                        if mode == 'aof-oversized': reply = b'-ERR ' + b'x' * 128 + b'\r\n'
                        if mode == 'aof-trailing': reply += b'+OK\r\n'
                        if mode == 'aof-short':
                            connection.sendall(b'*2\r\n:1\r\n')
                            return
                        if mode == 'aof-eof': return
                        if mode == 'aof-hang':
                            self.stopping.wait(1.4)
                            return
                        if mode == 'aof-held':
                            self.barrier_entered.set()
                            assert self.release_barrier.wait(3), 'barrier test did not release'
                        if mode == 'aof-replicas': reply = b'*2\r\n:1\r\n:2\r\n'
                        if mode == 'aof-fragmented':
                            connection.sendall(reply[:4])
                            time.sleep(.01)
                            reply = reply[4:]
                    elif args[0] == b'RESET':
                        authenticated, selected = False, False
                        reply = b'-ERR\r\n' if mode == 'reset-error' else b'+RESET\r\n'
                    else:
                        raise AssertionError(args)
                    if mode == 'fragmented' and args[0] == b'SET':
                        connection.sendall(reply[:1])
                        time.sleep(.01)
                        reply = reply[1:]
                    connection.sendall(reply)
        except (OSError, ssl.SSLError):
            pass  # Deliberate timeout, cancellation and poisoned connection cases.
        except Exception as error:
            with self.lock: self.errors.append(traceback.format_exc())

    def close(self):
        self.stopping.set()
        self.release_barrier.set()
        self.listener.close()
        self.thread.join(2)
        for worker in self.workers: worker.join(4)
        assert not self.errors, self.errors


def exchange(port, message, timestamp=None, key=KEY, duplicate=False, body=b'event', h2=False, abort_when=None):
    signed_timestamp = SIGNED_TIME if timestamp is None else timestamp
    timestamp = str(int(time.time()) if timestamp is None else timestamp)
    digest = hmac.new(key.encode(), message.encode()+b'.'+timestamp.encode()+b'.'+body,
                      hashlib.sha256).digest()
    signature = base64.b64encode(digest).decode()
    fields = f'webhook-id: {message}\r\nwebhook-timestamp: {timestamp}\r\nwebhook-signature: v1,{signature}\r\n'
    if duplicate: fields += f'webhook-id: {message}\r\n'
    target='/webhook'
    if SIGNED:
        target='/signed?event='+message
        date=formatdate(signed_timestamp, usegmt=True)
        digest='SHA-256='+base64.b64encode(hashlib.sha256(body).digest()).decode()
        canonical=f'billing-key\nPOST {target}\ndate: {date}\ndigest: {digest}\n'
        signature=base64.b64encode(hmac.new(key.encode(),canonical.encode(),hashlib.sha256).digest()).decode()
        fields=f'Authorization: Signature keyId="billing-key",algorithm="hmac-sha256",headers="@request-target date digest",signature="{signature}"\r\nDate: {date}\r\nDigest: {digest}\r\n'
        if duplicate: fields+=f'Date: {date}\r\n'
    if h2:
        headers=[tuple(line.split(': ',1)) for line in fields.strip().split('\r\n')]
        return h2_request(port,target,headers,body,method='POST')[0]
    wire = (f'POST {target} HTTP/1.1\r\nHost: local\r\nConnection: close\r\n'+fields+
            f'Content-Length: {len(body)}\r\n\r\n').encode()+body
    with socket.create_connection(('127.0.0.1', port), timeout=8) as connection:
        connection.sendall(wire)
        if abort_when is not None:
            assert abort_when.wait(2), 'service did not enter held barrier'
            return None  # Close the downstream while its claim awaits confirmation.
        data=b''
        while True:
            chunk=connection.recv(65536)
            if not chunk: break
            data+=chunk
    return int(data.split(b' ',2)[1])


@contextmanager
def gateway(args, source, store, directory):
    root=directory / str(time.monotonic_ns())
    root.mkdir()
    shutil.copytree(source.parent/'clients',root/'clients')
    shutil.copytree(source.parent/'middleware',root/'middleware')
    with socket.socket() as probe:
        probe.bind(('127.0.0.1',0)); port=probe.getsockname()[1]
    path=root/'auth.rut'
    path.write_text(source.read_text().replace('listen :8080',f'listen :{port}'))
    endpoint=dict(address='127.0.0.1',port=store.port,poolIdleMs=5000)
    if args.tls:
        endpoint.update(tls=True,caFile=str(Path(args.testdata)/'localhost_cert.pem'),serverName='localhost')
    import json
    env=dict(os.environ,STANDARD_WEBHOOK_RAW_KEY=KEY,REPLAY_NAMESPACE='replay:billing',SIGNED_REQUEST_KEY=KEY,
             REDIS_ENDPOINT=json.dumps(endpoint),REDIS_USERNAME='gateway',
             REDIS_PASSWORD='service-password',REDIS_DATABASE='1')
    log=root/'gateway.log'
    with log.open('w') as output:
        process=subprocess.Popen([args.server,str(path),'--backend',args.backend,'--opt',str(getattr(args,'opt',2)),
                                  '--no-pin','--shards','2','--drain','0',
                                  '--max-connections-per-shard','128'],env=env,
                                 stdout=output,stderr=subprocess.STDOUT)
    try:
        deadline=time.monotonic()+60
        while True:
            if process.poll() is not None:
                if args.backend=='io_uring' and 'io_uring is unavailable' in log.read_text():
                    raise SystemExit(77)
                raise AssertionError(log.read_text())
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.1):break
            except OSError:
                assert time.monotonic()<deadline,log.read_text()
                time.sleep(.025)
        path.unlink();shutil.rmtree(root/'clients');shutil.rmtree(root/'middleware')
        yield port
    finally:
        process.terminate()
        try:process.wait(5)
        except subprocess.TimeoutExpired:process.kill();process.wait()
        assert KEY not in log.read_text() and 'service-password' not in log.read_text()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--server',required=True)
    parser.add_argument('--source',required=True)
    parser.add_argument('--testdata',required=True)
    parser.add_argument('--backend',required=True)
    parser.add_argument('--tls',action='store_true')
    parser.add_argument("--signed",action="store_true")
    parser.add_argument('--durable',action='store_true')
    parser.add_argument('--opt',type=int,choices=(0,2),default=2)
    args=parser.parse_args()
    global SIGNED
    SIGNED=args.signed
    store=Store(Path(args.testdata),args.tls,args.durable)
    try:
        with tempfile.TemporaryDirectory(prefix='rut-auth-replay-') as tmp:
            with gateway(args,Path(args.source).resolve(),store,Path(tmp)) as port:
                for name,options in [('wrong-key',dict(key='wrong')),('old',dict(timestamp=1)),
                                     ('future',dict(timestamp=int(time.time())+900)),
                                     ('duplicate',dict(duplicate=True))]:
                    before=len(store.commands)
                    assert exchange(port,name,**options)==401
                    assert len(store.commands)==before
                assert exchange(port,'h2-message',h2=True)==204
                assert exchange(port,'h2-message',h2=True)==409
                before=len(store.commands)
                assert exchange(port,'h2-duplicate',duplicate=True,h2=True)==401
                assert len(store.commands)==before
                assert exchange(port,'one')==204
                assert exchange(port,'one')==409
                # A new signature/timestamp or body cannot re-admit the signed event ID.
                assert exchange(port,'one',body=b'changed')==(204 if SIGNED else 409)
                with ThreadPoolExecutor(max_workers=8) as pool:
                    results=list(pool.map(lambda _:exchange(port,'concurrent'),range(12)))
                assert results.count(204)==1 and results.count(409)==11,results
                for mode in ['auth-error','select-error','set-error','set-wrong','set-trailing',
                             'set-eof','set-timeout','reset-error','fragmented']:
                    with store.lock:store.mode=mode
                    assert exchange(port,mode)==(204 if mode=='fragmented' else 503),mode
                with store.lock:store.mode='normal'
                # Applied-but-unacknowledged SET/RESET cannot become a new allow.
                for name in ['set-eof','set-timeout','reset-error']:
                    assert exchange(port,name)==409,name
                if args.durable:
                    uncertain = ['aof-error', 'aof-timeout', 'aof-negative', 'aof-local',
                                 'aof-type', 'aof-arity', 'aof-nested', 'aof-overflow',
                                 'aof-oversized', 'aof-trailing', 'aof-short',
                                 'aof-eof', 'aof-hang']
                    for mode in uncertain + ['aof-replicas', 'aof-fragmented']:
                        with store.lock: store.mode=mode
                        assert exchange(port,mode)==(204 if mode in ('aof-replicas','aof-fragmented') else 503),mode
                    with store.lock: store.mode='normal'
                    for name in uncertain:
                        assert exchange(port,name)==409,name
                    with store.lock: store.mode='aof-held'
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        pending=pool.submit(exchange,port,'barrier-held')
                        assert store.barrier_entered.wait(2)
                        time.sleep(.05)
                        assert not pending.done(), 'admission preceded local fsync acknowledgement'
                        store.release_barrier.set()
                        assert pending.result(timeout=4)==204
                    store.barrier_entered.clear()
                    store.release_barrier.clear()
                    assert exchange(port,'cancelled-at-barrier',abort_when=store.barrier_entered) is None
                    store.release_barrier.set()
                    with store.lock: store.mode='normal'
                    assert exchange(port,'cancelled-at-barrier')==409
            # Same authoritative store survives gateway restart.
            with gateway(args,Path(args.source).resolve(),store,Path(tmp)) as port:
                assert exchange(port,'one')==409
                assert exchange(port,'new-after-restart')==204
        print('PASS: replay identity, concurrency, restart, service and cleanup failures')
    finally:store.close()
    return 0


if __name__=='__main__':raise SystemExit(main())
