from pathlib import Path
import subprocess,re
r=Path('/tmp/rut-bounded-followup-20260928');lab=r/'ebpf-tools'
log=(lab/'test-combined-fin-network.log').read_text()
m=re.search(r'(\d+) passed, (\d+) failed, (\d+) checks, (\d+) failed checks',log)
assert m and int(m[1])>=1425 and int(m[2])==0 and int(m[4])==0,'network regression gate failed'
assert 'PASS: bounded_combined_final_write_accounts_after_peer_eof' in log
cmd=['python3',str(lab/'matrix_guarded.py'),'--output',str(r/'combined-fin-full-acceptance'),'--rut',str(lab/'rut-combined-fin-ordered'),'--converter',str(r/'rut-nginx-convert-baseline'),'--wrk','/tmp/pr-watchdog/hurricane1026_Rut_687/wrk-boringssl-src2/wrk','--server-cpu','2','--origin-cpu','3','--client-cpus','4,5','--front-port','8987','--origin-port','9987','--keepalive-header','implicit','--first-engine','nginx','--profile','acceptance','--duration','5','--warmup','2','--repeats','3','--static-profile','native-body','--proxy-profile','converter-strict','--tls-cert','/tmp/rut-clean-bench/tls2/cert.pem','--tls-key','/tmp/rut-clean-bench/tls2/key.pem','--transports','http','https','--body-sizes','16','1024','65536','1048576','--scenarios','static-close','static-keepalive','proxy-close','proxy-keepalive','--concurrency','1','32','128']
with (lab/'accept-combined-fin-full.log').open('w') as f:p=subprocess.run(cmd,stdout=f,stderr=f)
print('full acceptance exit',p.returncode,flush=True)
raise SystemExit(p.returncode)
