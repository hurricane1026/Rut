from pathlib import Path
import subprocess,shutil,json
r=Path('/tmp/rut-bounded-followup-20260928');b=r/'ipo-build';lab=r/'ebpf-tools'
with (lab/'configure-ipo.log').open('w') as f:
 subprocess.run(['cmake','-S',str(r/'ipo-source'),'-B',str(b),'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=/usr/bin/clang','-DCMAKE_CXX_COMPILER=/usr/bin/clang++','-DLLVM_DIR=/usr/lib64/cmake/llvm','-DRUT_ENABLE_IPO=ON'],stdout=f,stderr=f,check=True)
commands=json.loads((b/'compile_commands.json').read_text())
runtime=next(c for c in commands if c['file'].endswith('/src/runtime/io_uring_backend.cc'))
assert '-flto' in runtime['command'], 'IPO requested but not active'
with (lab/'build-ipo.log').open('w') as f:
 subprocess.run(['cmake','--build',str(b),'--target','rut','-j','2'],stdout=f,stderr=f,check=True)
shutil.copy(b/'src/rut',lab/'rut-ipo')
print('IPO build completed',flush=True)
