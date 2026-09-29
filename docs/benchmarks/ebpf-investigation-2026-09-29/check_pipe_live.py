import argparse, hashlib, http.client, json, os, socket, subprocess, time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('binary');p.add_argument('output');p.add_argument('--trace',action='store_true');a=p.parse_args()
root=Path('/tmp/rut-bounded-followup-20260928');repo=Path('/home/hurricane/private/code/Rut-s1');out=root/a.output;out.mkdir()
case=root/'combined-fin-full-acceptance/http-1048576-proxy-keepalive';image=(repo/'tests/pinned-nginx-image.txt').read_text().strip()
def ready(port):
    for _ in range(200):
        try:
            with socket.create_connection(('127.0.0.1',port),.1):return
        except OSError:time.sleep(.05)
    raise RuntimeError('not ready: '+str(port))
def count_fds(pid):return len(list(Path(f'/proc/{pid}/fd').iterdir()))
for port in (8987,9987):
    with socket.socket() as s:
        if s.connect_ex(('127.0.0.1',port))==0:raise RuntimeError('port busy: '+str(port))
origin=None;proc=None;trace=None;rows=[]
try:
    origin=subprocess.check_output(['docker','run','-d','--rm','--network','host','--cpuset-cpus','3','--mount',f'type=bind,src={case}/origin.conf,dst=/etc/nginx/nginx.conf,readonly','--mount',f'type=bind,src={case}/payloads,dst=/benchmark-payloads,readonly',image,'nginx','-g','daemon off;'],text=True).strip();ready(9987)
    with (out/'server.log').open('w') as f:proc=subprocess.Popen(['taskset','-c','2',a.binary,str(case/'proxy.rut'),'--shards','1','--no-pin','--drain','1','--opt','2'],stdout=f,stderr=f)
    ready(8987);time.sleep(.1);before=count_fds(proc.pid)
    if a.trace:
        symbol='_ZN3rut14IoUringBackend20add_body_pipe_spliceEijRNS_16ResponseBodyPipeEb'
        script=out/'pipe.bt'
        script.write_text(f"""fentry:skb_copy_datagram_iter /pid == {proc.pid}/ {{ @copy_calls = count(); @copy_bytes = sum(args.len); }}
fentry:tcp_splice_read {{ @splice_read_calls[pid, comm, cpu] = count(); }}
fexit:tcp_splice_read /retval > 0/ {{ @splice_read_bytes[pid, comm, cpu] = sum(retval); }}
fentry:splice_to_socket {{ @splice_send_calls[pid, comm, cpu] = count(); }}
fexit:splice_to_socket /retval > 0/ {{ @splice_send_bytes[pid, comm, cpu] = sum(retval); }}
BEGIN {{ printf("PIPE_TRACE_READY\\n"); }}
interval:s:8 {{ exit(); }}
""")
        with (out/'trace.log').open('w') as f, (out/'trace.stderr').open('w') as err:
            trace=subprocess.Popen(['python3',str(root/'ebpf-tools/bpftrace-container.py'),'-B','line',str(script)],stdout=f,stderr=err)
        for _ in range(200):
            if 'PIPE_TRACE_READY' in (out/'trace.log').read_text():break
            if trace.poll() is not None:raise RuntimeError('trace failed: '+(out/'trace.stderr').read_text())
            time.sleep(.05)
        else:raise RuntimeError('trace readiness timeout')
    for mode in ('close','keepalive','slow'):
        conn=None
        try:
            for i in range(10):
                if conn is None:conn=http.client.HTTPConnection('127.0.0.1',8987,timeout=5)
                headers={'Host':'client.example'}
                if mode=='close':headers['Connection']='close'
                conn.request('GET','/proxy',headers=headers);response=conn.getresponse();assert response.status==200
                if mode=='slow':
                    chunks=[]
                    while True:
                        chunk=response.read(8192)
                        if not chunk:break
                        chunks.append(chunk);time.sleep(.001)
                    body=b''.join(chunks)
                else:body=response.read()
                assert body==b'x'*1048576,(mode,i,len(body))
                if mode=='close':conn.close();conn=None
            rows.append({'mode':mode,'requests':10,'exact_body':True});print(rows[-1],flush=True)
        finally:
            if conn:conn.close()
    for i in range(20):
        with socket.create_connection(('127.0.0.1',8987),3) as s:
            s.sendall(b'GET /proxy HTTP/1.1\r\nHost: client.example\r\n\r\n');assert s.recv(1024)
    conn=http.client.HTTPConnection('127.0.0.1',8987,timeout=5)
    try:
        conn.request('GET','/proxy',headers={'Host':'client.example'});r=conn.getresponse();assert r.status==200 and r.read()==b'x'*1048576
    finally:conn.close()
    if trace:
        assert trace.wait(timeout=20)==0,(out/'trace.stderr').read_text()
    time.sleep(1);after=count_fds(proc.pid)
    result={'binary':a.binary,'sha256':hashlib.sha256(Path(a.binary).read_bytes()).hexdigest(),'rows':rows,'aborted_clients':20,'post_abort_body_check':True,'fds_before':before,'fds_after':after,'pipe_admission_count':None,'performance_claim':False,'server_pid':proc.pid,'trace_requested':a.trace}
    assert after==before,result
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(result,flush=True)
finally:
    if trace and trace.poll() is None:trace.terminate();trace.wait(timeout=10)
    if proc and proc.poll() is None:proc.terminate();proc.wait(timeout=10)
    if origin:subprocess.run(['docker','stop',origin],stdout=subprocess.DEVNULL,check=True)
