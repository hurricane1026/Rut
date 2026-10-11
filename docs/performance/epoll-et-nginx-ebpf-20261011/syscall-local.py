import os,pathlib,subprocess,json
root=pathlib.Path('/home/hurricane/private/code/rut-performance-checkpoints/epoll-et-nginx-bpf-20261011');root.mkdir(exist_ok=True)
env=os.environ.copy();env.pop('DOCKER_HOST',None)
for k in list(env):
 if k.startswith('RUT_'):del env[k]
env.update(AUDIT_ENGINES='epoll,nginx',RUT_STUDY_EPOLL_ACCEPT_BATCH='16',RUT_STUDY_REQUEST_POLICY_VALIDATION_REUSE='on',RUT_AUDIT_NGINX_MULTI_ACCEPT='on')
for mode in ('proxy-close','proxy-keepalive'):
 env['RUT_STUDY_EPOLL_ET']='on'
 env['RUT_STUDY_EPOLL_STABLE_UPSTREAM']='on'
 print('START',mode,flush=True)
 r=subprocess.run(['bash','/tmp/rut-et-stable-bpf.sh',str(root/mode),mode],cwd='/tmp/rut-ws-pr-20261010',env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 (root/(mode+'.log')).write_text(r.stdout)
 print('DONE',mode,r.returncode,flush=True)
 if r.returncode:raise SystemExit(r.stdout[-4000:])
