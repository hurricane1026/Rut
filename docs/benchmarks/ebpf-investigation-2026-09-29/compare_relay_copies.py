from pathlib import Path
import subprocess,os,time,signal,sys,json
root=Path('/tmp/rut-bounded-followup-20260928'); out=root/sys.argv[1];out.mkdir();tools=root/'ebpf-tools'
for mode in ['copy','splice','uring-splice']:
 dest=out/mode;dest.mkdir();proc=None;trace=None
 try:
  with (dest/'relay.log').open('w') as log:
   proc=subprocess.Popen([str(tools/'splice-relay-probe'),mode,'65536','gate'],stdout=log,stderr=log)
  deadline=time.monotonic()+10
  while '"ready":true' not in (dest/'relay.log').read_text():
   assert proc.poll() is None and time.monotonic()<deadline
   time.sleep(.05)
  with (dest/'collector.log').open('w') as log:
   trace=subprocess.Popen(['python3',str(tools/'trace_relay_copies.py'),'--pid',str(proc.pid),'--duration','24','--groups','relay-copies','--bpftrace',str(tools/'bpftrace-container.py'),'--output',str(dest/'trace')],stdout=log,stderr=log)
  raw=dest/'trace/trace.jsonl';deadline=time.monotonic()+60
  while not raw.exists() or 'RUT_TRACE_READY' not in raw.read_text():
   assert trace.poll() is None and time.monotonic()<deadline
   time.sleep(.05)
  assert 'WARNING:' not in raw.read_text()
  os.kill(proc.pid,signal.SIGUSR1)
  assert trace.wait(timeout=60)==0
  assert '"body_verified":true' in (dest/'relay.log').read_text()
  os.kill(proc.pid,signal.SIGUSR1);assert proc.wait(timeout=10)==0
  print(mode,'complete',flush=True)
 finally:
  if trace and trace.poll() is None:trace.terminate();trace.wait(timeout=15)
  if proc and proc.poll() is None:
   # All probe processes have their own 120-second alarms; teardown closes sockets.
   proc.terminate();proc.wait(timeout=10)
