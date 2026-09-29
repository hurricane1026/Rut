import argparse, hashlib, http.client, json, os, signal, socket, subprocess, threading, time
from pathlib import Path
root=Path('/tmp/rut-bounded-followup-20260928')
def payload(n):
    block=bytes(range(251));return block*(n//len(block))+block[:n%len(block)]
def header(n):return f'HTTP/1.1 200 OK\r\nContent-Length: {n}\r\nContent-Type: application/octet-stream\r\n\r\n'.encode()
def serve(client):
    with client:
        try:
            client.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1);request=b''
            while b'\r\n\r\n' not in request:
                chunk=client.recv(4096)
                if not chunk:return
                request+=chunk
            path=request.split(b' ')[1].decode();n=8*1048576 if path.endswith('/backpressure') else 1048576;body=payload(n)
            client.sendall(header(n)+body[:131072])
            if path.endswith('/fragments'):
                for b in body[131072:131372]:client.sendall(bytes([b]));time.sleep(.002)
                client.sendall(body[131372:])
            elif path.endswith('/eof') or path.endswith('/stall'):
                client.sendall(body[131072:204800])
                if path.endswith('/stall'):time.sleep(2.3)
            else:client.sendall(body[131072:])
        except (BrokenPipeError,ConnectionResetError):pass
if len(os.sys.argv)>1 and os.sys.argv[1]=='--origin':
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('127.0.0.1',9987));listener.listen(64)
        while True:
            c,_=listener.accept();threading.Thread(target=serve,args=(c,),daemon=True).start()
    raise SystemExit
p=argparse.ArgumentParser();p.add_argument('binary');p.add_argument('output');a=p.parse_args();out=root/a.output;out.mkdir()
config=(root/'combined-fin-full-acceptance/http-1048576-proxy-keepalive/proxy.rut').read_text();assert 'response_read_timeout: 60s' in config
(out/'diagnostic.rut').write_text(config.replace('response_read_timeout: 60s','response_read_timeout: 1s'))
def ready(port):
    for _ in range(200):
        try:
            with socket.create_connection(('127.0.0.1',port),.1):return
        except OSError:time.sleep(.05)
    raise RuntimeError('not ready')
origin=None;proc=None;results=[]
try:
    origin=subprocess.Popen(['taskset','-c','3','python3',__file__,'--origin']);ready(9987)
    with (out/'server.log').open('w') as f:proc=subprocess.Popen(['taskset','-c','2',a.binary,str(out/'diagnostic.rut'),'--shards','1','--no-pin','--drain','1','--opt','2'],stdout=f,stderr=f)
    ready(8987)
    for case in ('fragments','eof','stall','backpressure','full'):
        conn=http.client.HTTPConnection('127.0.0.1',8987,timeout=10);conn.connect()
        try:
            if case=='backpressure':conn.sock.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,65536)
            conn.request('GET','/proxy/'+case,headers={'Host':'client.example'});response=conn.getresponse();assert response.status==200
            n=8*1048576 if case=='backpressure' else 1048576
            if case=='backpressure':time.sleep(1.3)
            incomplete=False
            try:body=response.read()
            except http.client.IncompleteRead as e:body=e.partial;incomplete=True
            expected=n
            if case=='eof':expected=204800
            if case=='stall':expected=((len(header(n))+204800)//4096)*4096-len(header(n))
            assert body==payload(expected),(case,len(body),expected,incomplete)
            assert incomplete==(case in ('eof','stall')),(case,incomplete)
            results.append({'case':case,'bytes':len(body),'exact_body_or_prefix':True,'incomplete':incomplete});print(results[-1],flush=True)
        finally:conn.close()
    (out/'result.json').write_text(json.dumps({'binary':a.binary,'sha256':hashlib.sha256(Path(a.binary).read_bytes()).hexdigest(),'diagnostic_timeout_seconds':1,'acceptance_configuration_changed':False,'results':results,'performance_claim':False},indent=2)+'\n')
finally:
    if proc and proc.poll() is None:proc.terminate();proc.wait(timeout=10)
    if origin and origin.poll() is None:origin.terminate();origin.wait(timeout=5)
