import os,json,time,socket,subprocess,http.client,sys
from pathlib import Path
root=Path('/tmp/rut-bounded-followup-20260928'); repo=Path('/home/hurricane/private/code/Rut-s1')
out=root/sys.argv[1];out.mkdir()
image=(repo/'tests/pinned-nginx-image.txt').read_text().strip()
wrk='/tmp/pr-watchdog/hurricane1026_Rut_687/wrk-boringssl-src2/wrk'
def ready(port):
 for _ in range(200):
  try:
   with socket.create_connection(('127.0.0.1',port),.1):return
  except OSError:time.sleep(.05)
 raise RuntimeError('not ready')
def start(ev,conf,cpu,user=False):
 args=['docker','run','-d','--rm','--network','host','--cpuset-cpus',str(cpu)]
 if user:args+=['--user',f'{os.getuid()}:{os.getgid()}', '--tmpfs', f'/var/cache/nginx:uid={os.getuid()},gid={os.getgid()},mode=0755']
 args+=['--mount',f'type=bind,src={ev}/{conf},dst=/etc/nginx/nginx.conf,readonly','--mount',f'type=bind,src={ev}/payloads,dst=/benchmark-payloads,readonly',image,'nginx','-g','daemon off;']
 return subprocess.check_output(args,text=True).strip()
def stats(pid):
 p=Path(f'/proc/{pid}');return {'stat':(p/'stat').read_text(),'schedstat':(p/'schedstat').read_text()}
for size,c,mode in [('65536',1,'close'),('65536',1,'keepalive')]:
 ev=root/'buffered-more-matrix-quick-r2'/f'http-{size}-proxy-{mode}';origin=start(ev,'origin.conf',3)
 try:
  ready(9987)
  for engine in ['rut-fin','nginx']:
   name=f'{size}-c{c}-{mode}-{engine}';dest=out/name;dest.mkdir();proc=None;cid=None;trace=None
   try:
    if engine.startswith('rut'):
     with (dest/'server.log').open('w') as f:
      proc=subprocess.Popen(['taskset','-c','2',str(root/('ebpf-tools/rut-small-poll-first' if engine=='rut-base' else 'ebpf-tools/rut-combined-fin-ordered')),str(ev/'proxy.rut'),'--shards','1','--no-pin','--drain','1','--opt','2'],stdout=f,stderr=f)
     pid=proc.pid
    else:
     cid=start(ev,'proxy-nginx.conf',2,True)
     master=int(subprocess.check_output(['docker','inspect','-f','{{.State.Pid}}',cid],text=True))
     for _ in range(100):
      children=Path(f'/proc/{master}/task/{master}/children').read_text().split()
      if children:break
      time.sleep(.05)
     pid=int(children[0])
    ready(8987)
    with socket.create_connection(('127.0.0.1',8987),timeout=3) as client:
     client.sendall(b'GET /proxy HTTP/1.1\r\nHost: client.example\r\nConnection: close\r\n\r\n')
     r=http.client.HTTPResponse(client);r.begin();body=r.read();assert r.status==200 and body==b'x'*int(size)
    lua=ev/f'proxy-{mode}-rut-r1-c{c}.lua'
    load=['taskset','-c','4,5',wrk,f'-t{min(c,2)}',f'-c{c}','-s',str(lua),'--timeout','2s','http://127.0.0.1:8987/proxy']
    with (dest/'warmup.log').open('w') as f:subprocess.run(load+['-d2s'],check=True,stdout=f,stderr=f)
    with (dest/'collector.log').open('w') as f:
     trace=subprocess.Popen(['python3',str(root/'ebpf-tools/trace_response_stages.py'),'--pid',str(pid),'--duration','12','--groups','response-stages','--bpftrace',str(root/'ebpf-tools/bpftrace-container.py'),'--output',str(dest/'trace')],stdout=f,stderr=f)
    raw=dest/'trace/trace.jsonl';deadline=time.monotonic()+120
    while not raw.exists() or 'RUT_TRACE_READY' not in raw.read_text():
     if trace.poll() is not None or time.monotonic()>deadline:raise RuntimeError(f'trace failed {dest}')
     time.sleep(.05)
    before=stats(pid)
    with (dest/'wrk.log').open('w') as f:subprocess.run(load+['-d8s'],check=True,stdout=f,stderr=f)
    after=stats(pid)
    (dest/'process.json').write_text(json.dumps({'pid':pid,'before':before,'after':after,'body_check':True,'command':load},indent=2))
    assert trace.wait(timeout=120)==0, dest
    print(name,'complete',flush=True)
   finally:
    if trace and trace.poll() is None:trace.terminate();trace.wait(timeout=15)
    if proc and proc.poll() is None:proc.terminate();proc.wait(timeout=10)
    if cid:subprocess.run(['docker','stop',cid],stdout=subprocess.DEVNULL)
 finally:subprocess.run(['docker','stop',origin],stdout=subprocess.DEVNULL)
