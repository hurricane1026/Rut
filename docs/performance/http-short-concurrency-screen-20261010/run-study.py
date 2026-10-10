import os,pathlib,subprocess,json,hashlib,shutil
root=pathlib.Path('/home/hurricane/private/code/rut-performance-checkpoints/http-short-concurrency-screen-20261010');root.mkdir(exist_ok=True)
source=pathlib.Path('/tmp/rut-ws-pr-20261010');build=pathlib.Path('/tmp/rut-ws-pr-20261010-build/src');candidate=root/'candidate';candidate.mkdir(exist_ok=True)
for name in ('rut','rut-compile','rut-nginx-convert'):shutil.copy2(build/name,candidate/name)
env=os.environ.copy();env.pop('DOCKER_HOST',None)
for k in list(env):
 if k.startswith('RUT_'):del env[k]
env.update(RUT_STUDY_POLICY='current',RUT_STUDY_HTTP_SPLICE_CHUNK='256k',RUT_STUDY_HTTP_RELAY_RING='on',RUT_STUDY_HTTP_BYTE_YIELD='on')
(root/'source.json').write_text(json.dumps({'commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip(),'sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in candidate.iterdir()},'environment':{k:v for k,v in env.items() if k.startswith('RUT_')},'scope':'local single-core plaintext proxy, 4 pinned origin workers; not official cross-machine replication'},indent=2))
rows=[]
for size,buffer,label,engines in [(1024,16,'c128','uring,epoll,nginx'),(1024,16,'c512','epoll,nginx,uring'),(1024,16,'c1024','nginx,uring,epoll')]:
 args=['python3','scripts/nginx_benchmark/relay_compare.py','--rut',str(candidate/'rut'),'--converter',str(candidate/'rut-nginx-convert'),'--wrk','/home/hurricane/private/code/rut-nginx-gap-next-bench-20261004/wrk-boringssl-src2','--output',str(root/label),'--engines',engines,'--origin-workers','4','--origin-cpus','3,4,8,9','--origin-reuseport','on','--origin-pin-workers','--server-cpu','2','--client-cpus','5,7','--workers','1','--front-port','8604','--origin-port','8704','--concurrency',label[1:],'--keepalive-header','implicit','--proxy-profile','native-streaming','--native-origin-reuse','on','--native-request-policy','omit-connection','--native-nginx-buffering','off','--nginx-buffering','off','--nginx-buffer-kib',str(buffer),'--scenarios','proxy-close','--body-size',str(size),'--duration','12','--warmup','2','--repeats','1']
 print('START',label,flush=True)
 result=subprocess.run(args,cwd=source,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 (root/(label+'.log')).write_text(result.stdout)
 for line in result.stdout.splitlines():
  if line.startswith('{"requests'):
   row=json.loads(line);row['campaign']=label;rows.append(row)
 (root/'summary.json').write_text(json.dumps(rows,indent=2))
 print('DONE',label,result.returncode,'rows',len(rows),flush=True)
 if result.returncode:print(result.stdout[-6000:],flush=True);raise SystemExit(result.returncode)
