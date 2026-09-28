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
for size,c,mode in [('1048576',1,'keepalive'),('1048576',32,'keepalive')]:
 ev=root/'poll-first-matrix-quick-r1'/f'http-{size}-static-{mode}';origin=start(ev,'origin.conf',3)
 try:
  ready(9987)
  for engine in ['nginx','rut']:
   name=f'{size}-c{c}-{mode}-{engine}';dest=out/name;dest.mkdir();proc=None;cid=None;trace=None;client_proc=None
   try:
    if engine=='rut':
     with (dest/'server.log').open('w') as f:
      proc=subprocess.Popen(['taskset','-c','2',str(root/'ebpf-tools/rut-small-poll-first'),str(ev/'static.rut'),'--shards','1','--no-pin','--drain','1','--opt','2'],stdout=f,stderr=f)
     pid=proc.pid
    else:
     cid=start(ev,'static-nginx.conf',2,True)
     master=int(subprocess.check_output(['docker','inspect','-f','{{.State.Pid}}',cid],text=True))
     for _ in range(100):
      children=Path(f'/proc/{master}/task/{master}/children').read_text().split()
      if children:break
      time.sleep(.05)
     pid=int(children[0])
    ready(8987)
    with socket.create_connection(('127.0.0.1',8987),timeout=3) as client:
     client.sendall(b'GET /static HTTP/1.1\r\nHost: client.example\r\nConnection: close\r\n\r\n')
     r=http.client.HTTPResponse(client);r.begin();body=r.read();assert r.status==200 and body==b'x'*int(size)
    lua=ev/f'static-{mode}-rut-r1-c{c}.lua'
    load=['taskset','-c','4,5',wrk,f'-t{min(c,2)}',f'-c{c}','-s',str(lua),'--timeout','2s','http://127.0.0.1:8987/static']
    with (dest/'warmup.log').open('w') as f:subprocess.run(load+['-d2s'],check=True,stdout=f,stderr=f)
    before=stats(pid)
    with (dest/'wrk.log').open('w') as f:
     client_proc=subprocess.Popen(load+['-d30s'],stdout=f,stderr=f)
    for _ in range(200):
     if Path(f'/proc/{client_proc.pid}/exe').resolve()==Path(wrk):break
     time.sleep(.01)
    else:raise RuntimeError('wrk identity unavailable')
    with (dest/'collector.log').open('w') as f:
     trace=subprocess.Popen(['python3',str(root/'ebpf-tools/trace_skb_geometry.py'),'--pid',str(pid),'--pid',str(client_proc.pid),'--duration','12','--groups','skb-geometry','--bpftrace',str(root/'ebpf-tools/bpftrace-container.py'),'--output',str(dest/'trace')],stdout=f,stderr=f)
    assert trace.wait(timeout=120)==0, dest
    assert client_proc.wait(timeout=60)==0
    after=stats(pid)
    for filename in ['warmup.log','wrk.log']:
     m=next(l for l in (dest/filename).read_text().splitlines() if l.startswith('METRICS ')).split()[1:]
     assert not any(map(int,m[5:])),m
    (dest/'process.json').write_text(json.dumps({'pid':pid,'client_pid':client_proc.pid,'before':before,'after':after,'body_check':True,'command':load},indent=2))
    print(name,'complete',flush=True)
   finally:
    if client_proc and client_proc.poll() is None:client_proc.terminate();client_proc.wait(timeout=10)
    if trace and trace.poll() is None:trace.terminate();trace.wait(timeout=15)
    if proc and proc.poll() is None:proc.terminate();proc.wait(timeout=10)
    if cid:subprocess.run(['docker','stop',cid],stdout=subprocess.DEVNULL)
 finally:subprocess.run(['docker','stop',origin],stdout=subprocess.DEVNULL)
