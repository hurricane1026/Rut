#!/usr/bin/env python3
"""Controlled API-like origin: variable headers, service delay and response fragments."""
import argparse,asyncio,json,multiprocessing,os,signal,time
from pathlib import Path

def payload_for_path(request_path,payload,small_payload,small_path):
    return small_payload if small_payload is not None and request_path==small_path else payload

def worker(index,cpu,port,payload,delay_ms,fragment_bytes,fragment_delay_ms,small_payload,small_path):
    os.sched_setaffinity(0,{cpu})
    connections=0;requests=0;sample_count=0;service_sum_us=0;service_max_us=0
    async def handle(reader,writer):
        nonlocal connections,requests,sample_count,service_sum_us,service_max_us
        connections+=1;connection=(os.getpid()<<24)+connections;count=0
        try:
            while True:
                raw=await reader.readuntil(b'\r\n\r\n')
                if len(raw)>32768:break
                count+=1;requests+=1;started=time.monotonic_ns()
                request_path=raw.split(b' ',2)[1].decode('ascii','replace')
                body=payload_for_path(request_path,payload,small_payload,small_path)
                if delay_ms:await asyncio.sleep(delay_ms/1000)
                if requests%64==0:
                    elapsed=(time.monotonic_ns()-started)//1000;sample_count+=1;service_sum_us+=elapsed;service_max_us=max(service_max_us,elapsed)
                headers={}
                for line in raw.split(b'\r\n')[1:]:
                    if b':' in line:
                        key,value=line.split(b':',1);headers[key.lower()]=value.strip()
                close=headers.get(b'connection',b'').lower()==b'close'
                head=(f'HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nContent-Type: application/octet-stream\r\nX-Request-Id: {connection}-{count}\r\nConnection: '+('close' if close else 'keep-alive')+'\r\n\r\n').encode()
                marker=headers.get(b'x-rut-benchmark-preflight')
                if marker:os.write(1,f'marker={marker.decode()} connection={connection} requests={count}\n'.encode())
                if fragment_bytes:
                    writer.write(head);await writer.drain()
                    for off in range(0,len(body),fragment_bytes):
                        writer.write(body[off:off+fragment_bytes]);await writer.drain()
                        if off+fragment_bytes<len(body):await asyncio.sleep(fragment_delay_ms/1000)
                else:writer.write(head+body);await writer.drain()
                if close:break
        except (asyncio.IncompleteReadError,ConnectionError,asyncio.LimitOverrunError):pass
        finally:
            writer.close()
            try:await writer.wait_closed()
            except ConnectionError:pass
    async def serve():
        server=await asyncio.start_server(handle,'127.0.0.1',port,reuse_port=True,limit=32768)
        os.write(1,f'API_READY worker={index} pid={os.getpid()} cpu={cpu}\n'.encode())
        async with server:await server.serve_forever()
    def stop(_sig,_frame):
        os.write(1,('API_STATS '+json.dumps({'worker':index,'connections':connections,'requests':requests,'service_samples':sample_count,'service_sum_us':service_sum_us,'service_max_us':service_max_us})+'\n').encode())
        raise SystemExit(0)
    signal.signal(signal.SIGTERM,stop)
    asyncio.run(serve())

def main():
    p=argparse.ArgumentParser();p.add_argument('--port',type=int,required=True);p.add_argument('--cpus',required=True);p.add_argument('--payload',type=Path,required=True);p.add_argument('--small-payload',type=Path);p.add_argument('--small-path',default='/api4k');p.add_argument('--delay-ms',type=float,default=0);p.add_argument('--fragment-bytes',type=int,default=0);p.add_argument('--fragment-delay-ms',type=float,default=0)
    a=p.parse_args();payload=a.payload.read_bytes();small_payload=a.small_payload.read_bytes() if a.small_payload else None;children=[]
    def stop(_sig=None,_frame=None):
        for child in children:child.terminate()
        for child in children:child.join(3)
        raise SystemExit(0)
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    for index,cpu in enumerate(map(int,a.cpus.split(','))):
        child=multiprocessing.get_context("fork").Process(target=worker,args=(index,cpu,a.port,payload,a.delay_ms,a.fragment_bytes,a.fragment_delay_ms,small_payload,a.small_path));child.start();children.append(child)
    while all(c.is_alive() for c in children):time.sleep(.1)
    stop()
if __name__=='__main__':main()
