import socket, threading, subprocess, time, http.client, json
from pathlib import Path
root=Path('/tmp/rut-bounded-followup-20260928')
out=root/'buffered-more-stall-r2';out.mkdir(exist_ok=False)
body=b'x'*1048576
header=b'HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n'
rows=[]
with socket.socket() as listener:
 listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('127.0.0.1',9987));listener.listen();listener.settimeout(5)
 for name in ['rut-bulk512','rut-buffered-more']:
  with (out/(name+'.log')).open('w') as log:
   proc=subprocess.Popen(['taskset','-c','2',str(root/'ebpf-tools'/name),str(root/'baseline-r1-1m/proxy.rut'),'--shards','1','--no-pin','--drain','1','--opt','2'],stdout=log,stderr=log)
   try:
    for _ in range(200):
     try:
      with socket.create_connection(('127.0.0.1',8987),.1):break
     except OSError:time.sleep(.05)
    else:raise RuntimeError('Rut startup failed')
    for burst in [16384,65536,524288]:
     for mode in ['close','keep-alive']:
      errors=[]
      def origin():
       try:
        c,_=listener.accept()
        with c:
         c.settimeout(3);request=b''
         while b'\r\n\r\n' not in request:request+=c.recv(4096)
         c.sendall(header+body[:burst]);time.sleep(.3);c.sendall(body[burst:])
       except BaseException as e:errors.append(repr(e))
      worker=threading.Thread(target=origin);worker.start()
      try:
       with socket.create_connection(('127.0.0.1',8987),1) as client:
        client.settimeout(.1);start=time.monotonic();client.sendall(('GET /proxy HTTP/1.1\r\nHost: client.example\r\n'+('Connection: close\r\n' if mode=='close' else '')+'\r\n').encode())
        response=http.client.HTTPResponse(client);response.begin();assert response.status==200
        target=(len(header)+burst)//4096*4096-len(header)
        prefix=response.read(target);elapsed=time.monotonic()-start
        assert prefix==body[:target] and elapsed<.1
        client.settimeout(3);rest=response.read();assert prefix+rest==body
        rows.append(dict(binary=name,burst=burst,connection=mode,eligible_prefix_bytes=target,prefix_ms=elapsed*1000,body_check=True))
        (out/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
        print(rows[-1],flush=True)
      finally:worker.join(5)
      assert not worker.is_alive() and not errors,errors
   finally:
    proc.terminate();proc.wait(timeout=10)
