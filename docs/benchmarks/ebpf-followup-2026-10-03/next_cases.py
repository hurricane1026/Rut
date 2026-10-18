import subprocess,sys,time,json
from pathlib import Path
root=Path("/home/hurricane/private/code/Rut")
stage=Path("/home/hurricane/private/code/rut-ebpf-20261003")
for _ in range(240):
    status=stage/"sidecar-1m-r2/status.json"
    if status.exists():
        record=json.loads(status.read_text())
        if not record.get("complete") or not record.get("valid"): raise SystemExit(str(record))
        break
    time.sleep(1)
else: raise SystemExit("prior case did not finish")
def run(name,argv):
    print("START",name,flush=True)
    with (stage/(name+".log")).open("w") as log:
        result=subprocess.run(argv,cwd=root,stdout=log,stderr=subprocess.STDOUT)
    print("DONE",name,result.returncode,flush=True)
    if result.returncode: raise SystemExit(result.returncode)

for name in ("sidecar-256k-r2","actual-rut-256k"):
    out=stage/name;out.mkdir(exist_ok=True)
    subprocess.run(["chcon","-t","container_file_t",str(out)],check=True)
common=["--server-cpu","2","--origin-cpu","3","--client-cpus","4,5","--concurrency","1","32","--warmup","1","--duration","5","--repeats","3"]
run("sidecar-256k-r2",["python3","scripts/kernel_relay_benchmark.py","--relay",str(stage/"relay-ebpf-r2"),"--loader",str(stage/"loader"),"--libc",str(stage/"libc.so.6"),"--wrk","/tmp/pr-watchdog/hurricane1026_Rut_687/wrk-boringssl-src2/wrk","--output",str(stage/"sidecar-256k-r2"),"--include-ebpf","--first-engine","ebpf","--body-size","262144",*common])
run("actual-rut-256k",["python3",str(stage/"actual_rut_baseline.py"),"--rut",str(root/"build/src/rut"),"--converter",str(root/"build/src/rut-nginx-convert"),"--wrk","/tmp/pr-watchdog/hurricane1026_Rut_687/wrk-boringssl-src2/wrk","--output",str(stage/"actual-rut-256k"),"--body-size","262144","--proxy-profile","native-streaming","--keepalive-header","implicit","--scenarios","proxy-keepalive",*common])
# One invocation keeps the container environment fixed. JSON includes requested
# mode so copy fallback samples remain in their intended eBPF group.
shell='for size in 16777216 536870912; do for chunk in 4096 16384 65536; do for n in 1 2 3; do for mode in off required required off; do /probe/loader --library-path /probe /probe/handoff-profile "$mode" --packet-verdict --coalesced-tail --size "$size" --prequeue 0 --delay-us 0 --slow-reader-us 0 --chunk-bytes "$chunk" || exit; done; done; done; done'
run("long-flows",["docker","run","--rm","--pull=never","--cap-drop","ALL","--cap-add","BPF","--cap-add","NET_ADMIN","--security-opt","label=disable","--mount",f"type=bind,src={stage},dst=/probe,readonly","--entrypoint","/bin/sh","nginx:latest","-c",shell])

out=stage/"cpu-placement";out.mkdir(exist_ok=True)
subprocess.run(["chcon","-t","container_file_t",str(out)],check=True)
run("cpu-placement",["python3","scripts/kernel_relay_benchmark.py","--relay",str(stage/"relay-ebpf-r2"),"--loader",str(stage/"loader"),"--libc",str(stage/"libc.so.6"),"--wrk","/tmp/pr-watchdog/hurricane1026_Rut_687/wrk-boringssl-src2/wrk","--output",str(out),"--include-ebpf","--body-size","1048576","--server-cpu","2","--origin-cpu","3","--client-cpus","4,5","--concurrency","1","32","--warmup","1","--duration","5","--repeats","1"])
