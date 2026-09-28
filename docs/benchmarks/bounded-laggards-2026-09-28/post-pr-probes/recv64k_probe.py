import os,json,time,socket,subprocess,signal
from pathlib import Path
root=Path('/tmp/rut-bounded-followup-20260928');out=root/'gap'/'recv64k';out.mkdir(exist_ok=True);hz=os.sysconf('SC_CLK_TCK')
image=Path('/home/hurricane/private/code/Rut-s1/tests/pinned-nginx-image.txt').read_text().strip()
wrk='/tmp/pr-watchdog/hurricane1026_Rut_687/wrk-boringssl-src2/wrk'
def ready(port):
 for i in range(100):
  try:
   with socket.create_connection(('127.0.0.1',port),.1):return
  except OSError:time.sleep(.05)
 raise RuntimeError('listener timeout')
def start_nginx(conf,cpu,payload=None):
 args=['docker','create','--pull=never','--network','host','--cpuset-cpus',str(cpu),'--ulimit','nofile=65536:65536','--mount',f'type=bind,src={conf},dst=/etc/nginx/nginx.conf,readonly']
 if payload:args+=['--mount',f'type=bind,src={payload},dst=/benchmark-payloads,readonly']
 cid=subprocess.check_output(args+[image,'nginx','-g','daemon off;'],text=True).strip()
 subprocess.run(['docker','start',cid],check=True,stdout=subprocess.DEVNULL)
 pid=int(subprocess.check_output(['docker','inspect','-f','{{.State.Pid}}',cid],text=True));return cid,pid
def stat_tree(pid):
 todo=[pid]; result=dict(user=0.,system=0.,minor_faults=0,major_faults=0,voluntary=0,involuntary=0,run_ns=0,wait_ns=0,timeslices=0,rss_bytes=0)
 while todo:
  p=todo.pop();base=Path(f'/proc/{p}')
  v=(base/'stat').read_text().rsplit(')',1)[1].split();result['user']+=int(v[11])/hz;result['system']+=int(v[12])/hz;result['minor_faults']+=int(v[7]);result['major_faults']+=int(v[9]);result['rss_bytes']+=int(v[21])*os.sysconf('SC_PAGE_SIZE')
  for t in (base/'task').iterdir():
   todo += [int(x) for x in (t/'children').read_text().split()]
   st=dict(x.split(':',1) for x in (t/'status').read_text().splitlines() if ':' in x)
   result['voluntary']+=int(st['voluntary_ctxt_switches']);result['involuntary']+=int(st['nonvoluntary_ctxt_switches'])
   ss=[int(x) for x in (t/'schedstat').read_text().split()]
   for k,n in zip(['run_ns','wait_ns','timeslices'],ss):result[k]+=n
 return result
results=[]
for size,conc in [('1m',32),('1m',128)]:
 ev=root/('baseline-r1-'+size);origin=None
 try:
  origin,_=start_nginx(ev/'origin.conf',3,ev/'payloads');ready(9987)
  for rep,engine in enumerate(['recv64k','rut','rut','recv64k']):
   cid=None;proc=None
   try:
    if engine=='nginx':cid,pid=start_nginx(ev/'proxy-nginx.conf',2)
    else:
     log=(out/f'{size}-{conc}-{rep}.server.log').open('w');proc=subprocess.Popen(['taskset','-c','2',str(root/'gap'/'rut-recv64k' if engine=='recv64k' else root/'gap'/'rut-cache256-final'),str(ev/'proxy.rut'),'--shards','1','--no-pin','--drain','1','--opt','2'],stdout=log,stderr=log);pid=proc.pid
    ready(8987)
    cmd=['taskset','-c','4,5',wrk,f'-t{min(conc,2)}',f'-c{conc}','-s',str(ev/f'proxy-close-rut-r1-c{conc}.lua'),'--timeout','2s','http://127.0.0.1:8987/proxy']
    subprocess.run(cmd+['-d2s'],check=True,stdout=subprocess.DEVNULL)
    before=stat_tree(pid);start=time.monotonic();raw=subprocess.check_output(cmd+['-d6s'],text=True);elapsed=time.monotonic()-start;after=stat_tree(pid)
    (out/f'{size}-{conc}-{rep}.wrk.log').write_text(raw)
    m=[x for x in raw.splitlines() if x.startswith('METRICS ')][0].split()[1:];requests=int(m[0]);duration=int(m[1])/1e6
    row={'size':size,'concurrency':conc,'engine':engine,'rep':rep,'requests':requests,'duration':duration,'elapsed':elapsed,'rps':requests/duration,'errors':[int(x) for x in m[5:]],'rss_bytes':after['rss_bytes']}
    for k in before:
     if k!='rss_bytes':row[k]=after[k]-before[k]
    for k in ['user','system']:row[k+'_us_per_request']=row[k]/requests*1e6
    results.append(row);(out/'cpu-results.json').write_text(json.dumps(results,indent=2));print(size,conc,engine,round(row['rps'],1),'user/sys us',round(row['user_us_per_request'],1),round(row['system_us_per_request'],1),flush=True)
   finally:
    if proc:
     proc.terminate()
     try:proc.wait(timeout=5)
     except subprocess.TimeoutExpired:proc.kill();proc.wait()
    if cid:subprocess.run(['docker','rm','-f',cid],stdout=subprocess.DEVNULL)
 finally:
  if origin:subprocess.run(['docker','rm','-f',origin],stdout=subprocess.DEVNULL)
