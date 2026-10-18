import sys
from pathlib import Path
import os
sys.path.insert(0, "/home/hurricane/private/code/Rut/scripts/nginx_benchmark")
import run as base
def busy():
    v=list(map(int,Path("/proc/stat").read_text().splitlines()[0].split()[1:]))
    return sum(v[i] for i in (0,1,2,5,6,7))/os.sysconf("SC_CLK_TCK")
original=base.Harness.wrk
def observed(self,*args,**kwargs):
    before=busy()
    result=original(self,*args,**kwargs)
    result["machine_busy_seconds"]=busy()-before
    return result
base.Harness.wrk=observed
raise SystemExit(base.main())
