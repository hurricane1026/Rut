from pathlib import Path
import subprocess,socket,time,json,hashlib
r=Path('/tmp/rut-bounded-followup-20260928');lab=r/'ebpf-tools';out=r/'file-prefix16-pipeline';out.mkdir()
body=bytes(65+(i*11+i//251+(i//4096)*7)%26 for i in range(1048576))
cfg=out/'static.rut';cfg.write_bytes(b'listen 127.0.0.1:8987\nroute GET "/static" { return response(200, body: "'+body+b'") }\n')
p=None
try:
 with (out/'server.log').open('w') as f:p=subprocess.Popen(['taskset','-c','2',str(lab/'rut-file-prefix16-aligned'),str(cfg),'--shards','1','--no-pin','--drain','1','--opt','2'],stdout=f,stderr=f)
 for _ in range(200):
  try:
   s=socket.create_connection(('127.0.0.1',8987),.1);break
  except OSError:time.sleep(.05)
 else:raise RuntimeError('server not ready')
 with s:
  s.settimeout(10)
  s.sendall(b'GET /static HTTP/1.1\r\nHost: localhost\r\n\r\n'*2+b'GET /static HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
  chunks=[]
  while True:
   b=s.recv(65536)
   if not b:break
   chunks.append(b)
   assert sum(map(len,chunks))<4*1048576
 wire=b''.join(chunks);offset=0
 for i in range(3):
  end=wire.index(b'\r\n\r\n',offset)+4;header=wire[offset:end];assert header.startswith(b'HTTP/1.1 200 ')
  fields=dict(l.split(b':',1) for l in header.split(b'\r\n')[1:] if b':' in l)
  lengths=[int(v) for k,v in fields.items() if k.lower()==b'content-length'];assert lengths==[len(body)]
  assert wire[end:end+len(body)]==body,(i,end,len(wire))
  offset=end+len(body)
 assert offset==len(wire)
 (out/'result.json').write_text(json.dumps({'responses':3,'exact_nonuniform_body':True,'pipeline_same_socket':True,'wire_bytes':len(wire),'body_sha256':hashlib.sha256(body).hexdigest()},indent=2))
 print('3 pipelined nonuniform 1 MiB responses passed',flush=True)
finally:
 if p and p.poll() is None:p.terminate();p.wait(timeout=10)
