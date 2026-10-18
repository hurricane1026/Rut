import json, subprocess
from pathlib import Path
root=Path('/home/hurricane/private/code/rut-opt-20261003')
repo=Path('/home/hurricane/private/code/Rut')
commands=[]
for body, cs in [(65536,[1]),(1048576,[32])]:
    for i,variant in enumerate(['baseline','candidate','candidate','baseline']):
        out=root/f'{body}-{i}-{variant}'
        cmd=['python3',str(repo/'scripts/nginx_benchmark/run.py'),'--rut',str(root/variant/'rut'),'--converter',str(root/variant/'rut-nginx-convert'),'--wrk','/tmp/pr-watchdog/hurricane1026_Rut_687/wrk-boringssl-src2/wrk','--output',str(out),'--server-cpu','2','--origin-cpu','3','--client-cpus','4,5','--keepalive-header','implicit','--body-size',str(body),'--concurrency',*map(str,cs),'--scenarios','proxy-close','proxy-keepalive','--warmup','1','--duration','5','--repeats','3','--first-engine',('nginx' if i%2==0 else 'rut')]
        commands.append(dict(body=body,variant=variant,index=i,command=cmd))
(root/'plan.json').write_text(json.dumps(commands,indent=2)+'\n')
status=[]
for entry in commands:
    print('start',entry['body'],entry['index'],entry['variant'],flush=True)
    with (root/f"{entry['body']}-{entry['index']}-{entry['variant']}.log").open('w') as log:
        result=subprocess.run(entry['command'],cwd=repo,stdout=log,stderr=subprocess.STDOUT)
    status.append(dict(body=entry['body'],index=entry['index'],variant=entry['variant'],returncode=result.returncode))
    (root/'status.json').write_text(json.dumps(status,indent=2)+'\n')
    print('done',status[-1],flush=True)
    if result.returncode: raise SystemExit(result.returncode)
