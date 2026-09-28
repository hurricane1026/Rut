import os,json,time,socket,subprocess,http.client,sys
from pathlib import Path
root=Path('/tmp/rut-bounded-followup-20260928');repo=Path('/home/hurricane/private/code/Rut-s1');out=root/sys.argv[1];out.mkdir()
candidate=sys.argv[2];baseline=str(root/'ebpf-tools/rut-bulk512');image=(repo/'tests/pinned-nginx-image.txt').read_text().strip();rows=[]
wrk='/tmp/pr-watchdog/hurricane1026_Rut_687/wrk-boringssl-src2/wrk'
def ready(port):
 for _ in range(200):
  try:
   with socket.create_connection(('127.0.0.1',port),.1):return
  except OSError:time.sleep(.05)
 raise RuntimeError('not ready')
def stat(pid):
 a=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
 r=dict(user_us=int(a[11])*10000,system_us=int(a[12])*10000,minor_faults=int(a[7]),rss_bytes=int(a[21])*4096,runqueue_us=0,voluntary=0,involuntary=0)
 for task in Path(f'/proc/{pid}/task').iterdir():
  try:
   r['runqueue_us']+=int((task/'schedstat').read_text().split()[1])/1000
   status=dict(line.split(':',1) for line in (task/'status').read_text().splitlines() if ':' in line)
   r['voluntary']+=int(status['voluntary_ctxt_switches']);r['involuntary']+=int(status['nonvoluntary_ctxt_switches'])
  except FileNotFoundError:pass
 return r
def metrics(raw):
 m=next(l for l in raw.splitlines() if l.startswith('METRICS ')).split()[1:]
 assert not any(map(int,m[5:])),m
 return int(m[0]),int(m[1])/1e6
cases=[('1m',32,'close'),('1m',128,'close'),('64k',1,'close'),('64k',1,'keepalive')]
if len(sys.argv)>3:cases=[x for x in cases if x[0]==sys.argv[3]]
for size,c,mode in cases:
 ev=root/('baseline-r1-'+size)
 origin=subprocess.check_output(['docker','run','-d','--rm','--network','host','--cpuset-cpus','3','--mount',f'type=bind,src={ev}/origin.conf,dst=/etc/nginx/nginx.conf,readonly','--mount',f'type=bind,src={ev}/payloads,dst=/benchmark-payloads,readonly',image,'nginx','-g','daemon off;'],text=True).strip()
 try:
  ready(9987)
  for rep,engine in enumerate(os.environ.get('PROBE_ORDER','candidate,baseline,baseline,candidate').split(',')):
   dest=out/f'{size}-c{c}-{mode}-{rep}-{engine}';dest.mkdir();proc=None
   try:
    binary=candidate if engine=='candidate' else baseline
    with (dest/'server.log').open('w') as f:proc=subprocess.Popen(['taskset','-c','2',binary,str(ev/'proxy.rut'),'--shards','1','--no-pin','--drain','1','--opt','2'],stdout=f,stderr=f)
    ready(8987)
    with socket.create_connection(('127.0.0.1',8987),timeout=3) as client:
     client.sendall(b'GET /proxy HTTP/1.1\r\nHost: client.example\r\nConnection: close\r\n\r\n')
     r=http.client.HTTPResponse(client);r.begin();assert r.status==200 and r.read()==b'x'*(1048576 if size=='1m' else 65536)
    lua=ev/f'proxy-{mode}-rut-r1-c{c}.lua'
    load=['taskset','-c','4,5',wrk,f'-t{min(c,2)}',f'-c{c}','-s',str(lua),'--timeout','2s','http://127.0.0.1:8987/proxy']
    raw=subprocess.check_output(load+['-d2s'],text=True);(dest/'warmup.log').write_text(raw);metrics(raw)
    (dest/'host-before.txt').write_text(subprocess.check_output(['ps','-eo','pid,pcpu,comm','--sort=-pcpu'],text=True));before=stat(proc.pid);raw=subprocess.check_output(load+['-d6s'],text=True);after=stat(proc.pid);(dest/'host-after.txt').write_text(subprocess.check_output(['ps','-eo','pid,pcpu,comm','--sort=-pcpu'],text=True));(dest/'wrk.log').write_text(raw);n,seconds=metrics(raw)
    row={'case':f'{size}-c{c}-{mode}','engine':engine,'rep':rep,'binary':binary,'requests':n,'seconds':seconds,'rps':n/seconds,'errors':[0]*5,'body_check':True,'rss_bytes':after['rss_bytes']}
    for k in ['user_us','system_us','minor_faults','runqueue_us','voluntary','involuntary']:row[k+'_per_request']=(after[k]-before[k])/n
    rows.append(row);(out/'results.json').write_text(json.dumps(rows,indent=2));print(row['case'],engine,round(row['rps'],1),'user/sys',round(row['user_us_per_request'],1),round(row['system_us_per_request'],1),flush=True)
   finally:
    if proc and proc.poll() is None:proc.terminate();proc.wait(timeout=10)
 finally:subprocess.run(['docker','stop',origin],stdout=subprocess.DEVNULL)
