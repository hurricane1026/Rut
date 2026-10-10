import json, os, pathlib, subprocess, time
frontend_pid = None
def descendants(pid):
    result = [pid]
    for current in result:
        try: children = pathlib.Path(f'/proc/{current}/task/{current}/children').read_text().split()
        except OSError: continue
        result.extend(int(p) for p in children)
    return result

def measured(harness, original, args, kwargs):
    label = args[-1] if args else kwargs.get('label', '')
    if label.endswith('-warmup'): return original(harness, *args, **kwargs)
    duration = args[-2]
    origins = json.loads((harness.out/'origin-worker-affinity.json').read_text())
    roles = {int(p['pid']): 'origin' for p in origins}
    roles.update({pid: 'frontend' for pid in descendants(frontend_pid)})
    controller = os.getpid()
    seeds = ''.join(f'@role[{p}] = {1 if r == "origin" else 2};' for p,r in roles.items())
    program = f'''config = {{ max_map_keys = 65536; }}
BEGIN {{ {seeds} printf("READY\\n"); }}
profile:hz:997 /@role[(int64)pid] == 2/ {{ @mode[comm, usermode] = count(); if (usermode) {{ @user[comm, ustack(1)] = count(); }} if (!usermode) {{ @kernel[comm, kstack(8)] = count(); }} }}
interval:s:{int(duration)+3} {{ exit(); }}
END {{ clear(@role); }}
'''
    script = harness.out/(label+'.bt');script.write_text(program)
    output = harness.out/(label+'.syscalls.jsonl')
    metadata = harness.out/(label+'.syscalls-processes.json')
    metadata.write_text(json.dumps({'roles':roles,'client_controller':controller,'window':'measurement plus up to 3 seconds idle; warmup/preflight excluded','elapsed':'includes blocking/scheduling; not CPU time'},indent=2))
    with output.open('w') as stream, (harness.out/(label+'.bpf.stderr')).open('w') as errors:
        proc = subprocess.Popen(['sudo','-n','/usr/bin/bpftrace','-B','line','-f','json',str(script)],stdout=stream,stderr=errors)
        deadline=time.monotonic()+20
        while 'READY' not in output.read_text():
            if proc.poll() is not None: raise RuntimeError('bpftrace failed: '+(harness.out/(label+'.bpf.stderr')).read_text())
            if time.monotonic()>deadline: raise RuntimeError('bpftrace startup timeout')
            time.sleep(.05)
        try: return original(harness,*args,**kwargs)
        finally: proc.wait(timeout=int(duration)+10)
