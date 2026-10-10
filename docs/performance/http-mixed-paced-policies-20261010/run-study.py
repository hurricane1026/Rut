import os,pathlib,shutil,subprocess,json,hashlib
root=pathlib.Path('/home/hurricane/private/code/rut-performance-checkpoints/http-mixed-paced-policies-20261010');root.mkdir(exist_ok=True)
source=pathlib.Path('/tmp/rut-ws-pr-20261010');build=pathlib.Path('/tmp/rut-ws-pr-20261010-build/src');candidate=root/'candidate';candidate.mkdir(exist_ok=True)
for name in ('rut','rut-compile','rut-nginx-convert'):shutil.copy2(build/name,candidate/name)
(root/'source.json').write_text(json.dumps({'commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip(),'sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in candidate.iterdir()},'goal_nginx_ratio':1.5,'small_p99_regression_limit':1.10},indent=2))
env=os.environ.copy();env.pop('DOCKER_HOST',None)
for key in list(env):
 if key.startswith('RUT_'):del env[key]
env['RUT_STUDY_POLICY']='current'
configs=[('current256','uring','256k',True,True,'80us',False,False,'current'),('latency256','uring','256k',True,True,'20us',False,False,'latency'),('balanced256','uring','256k',True,True,'80us',False,False,'balanced'),('throughput256','uring','256k',True,False,'80us',False,False,'throughput'),('nginx','nginx','128k',False,False,'80us',False,False,'current')]
rows=[]
for rep in range(3):
 for label,engine,chunk,ring,byte_gate,cq_wait,taskrun,early,policy in configs[rep:]+configs[:rep]:
  env['RUT_STUDY_POLICY']=policy;env['RUT_STUDY_HTTP_SPLICE_CHUNK']=chunk;env['RUT_STUDY_HTTP_RELAY_RING']='on' if ring else 'off';env['RUT_STUDY_HTTP_BYTE_YIELD']='on' if byte_gate else 'off';env['RUT_STUDY_HTTP_CQ_WAIT']=cq_wait;env['RUT_STUDY_HTTP_TASKRUN_YIELD']='on' if taskrun else 'off';env['RUT_STUDY_HTTP_SUBMIT_BEFORE_RELAY']='on' if early else 'off'
  cell=root/f'r{rep}-{label}'
  args=['python3','scripts/nginx_benchmark/relay_compare.py','--rut',str(candidate/'rut'),'--converter',str(candidate/'rut-nginx-convert'),'--wrk','/home/hurricane/private/code/rut-nginx-gap-next-bench-20261004/wrk-boringssl-src2','--output',str(cell),'--engines',engine,'--origin-workers','4','--origin-cpus','3,4,8,9','--origin-reuseport','on','--origin-pin-workers','--server-cpu','2','--client-cpus','5,7,6','--workers','1','--front-port','8604','--origin-port','8704','--concurrency','128','--keepalive-header','implicit','--proxy-profile','native-streaming','--native-origin-reuse','on','--native-nginx-buffering','off','--scenarios','proxy-keepalive','--body-size','1048576','--mixed-small-bytes','4096','--mixed-small-rate','1000','--small-connections','32','--mixed-client-cpus','5,7;6','--mixed-distinct-urls','--duration','12','--warmup','3','--repeats','1']
  print('START',rep,label,flush=True)
  result=subprocess.run(args,cwd=source,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  (root/f'r{rep}-{label}.log').write_text(result.stdout)
  print('DONE',rep,label,'exit',result.returncode,flush=True)
  for line in result.stdout.splitlines():
   if line.startswith('{"requests'):
    row=json.loads(line);row.update(configuration=label,rotation=rep,small_body=4096)
    row['payload_bytes_per_second']=row['large_client']['rps']*1048576+row['small_client']['rps']*4096
    rows.append(row);print(json.dumps(row),flush=True)
  (root/'summary.json').write_text(json.dumps(rows,indent=2))
  if result.returncode:print(result.stdout[-4000:],flush=True);raise SystemExit(result.returncode)
