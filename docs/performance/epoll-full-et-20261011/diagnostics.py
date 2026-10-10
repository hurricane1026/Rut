import os,pathlib,subprocess,json
source=pathlib.Path('/tmp/rut-ws-pr-20261010')
root=pathlib.Path('/home/hurricane/private/code/rut-performance-checkpoints/epoll-full-et-diagnostics-20261011')
root.mkdir(exist_ok=True)
base=os.environ.copy();base.pop('DOCKER_HOST',None)
for key in list(base):
 if key.startswith('RUT_'):del base[key]
base.update(RUT_STUDY_EPOLL_ET='on',RUT_STUDY_EPOLL_ACCEPT_BATCH='16',RUT_STUDY_HTTP_COALESCE_CLOSE='on',RUT_STUDY_REQUEST_POLICY_VALIDATION_REUSE='on',RUT_AUDIT_NGINX_MULTI_ACCEPT='on')
stages=[
 ('tls',['python3','/tmp/rut-full-et-tls-smoke.py'],dict(base)),
 ('protocol',['python3',str(source/'scripts/nginx_benchmark/protocol_strategy.py'),'--rut','/home/hurricane/private/code/rut-performance-checkpoints/epoll-full-et-ready-20261011/candidate/rut','--harness',str(source/'scripts/nginx_benchmark/run.py'),'--output',str(root/'protocol'),'--smoke','--engines','epoll','--cases','websocket-interactive-64','websocket-bulk-1m','streaming-bulk-64k','--duration','2','--connections-per-client','4'],dict(base)),
 ('bpf-lt',['bash','/tmp/rut-syscall-audit/run-bpf-et.sh',str(root/'bpf-lt'),'proxy-close'],dict(base,RUT_STUDY_EPOLL_ET='off',AUDIT_ENGINES='epoll,uring,nginx')),
 ('bpf-et',['bash','/tmp/rut-syscall-audit/run-bpf-et.sh',str(root/'bpf-et'),'proxy-close'],dict(base,AUDIT_ENGINES='epoll'))
]
results=[]
for label,args,env in stages:
 print('START',label,flush=True)
 result=subprocess.run(args,cwd=source,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 (root/(label+'.log')).write_text(result.stdout)
 results.append(dict(stage=label,returncode=result.returncode))
 (root/'stages.json').write_text(json.dumps(results,indent=2))
 print('DONE',label,result.returncode,flush=True)
 if result.returncode:raise SystemExit(result.stdout[-3000:])
