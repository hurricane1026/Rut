import sys, importlib.util, subprocess
from pathlib import Path
spec=importlib.util.spec_from_file_location('benchrun','/home/hurricane/private/code/Rut-s1/scripts/nginx_benchmark/run.py')
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
def guard(path):
 raw=subprocess.check_output(['ps','-eo','pid,comm,pcpu'],text=True);path.write_text(raw)
 busy=[]
 for row in raw.splitlines()[1:]:
  fields=row.split()
  if len(fields)>=2 and (fields[1] in {'clang++','clang','cc1','cc1plus','ninja','make'} or fields[1].startswith('test_')):busy.append(row)
 if busy:raise RuntimeError('benchmark host busy: '+repr(busy))
original=m.Harness.wrk
def wrk(self,work,close,concurrency,duration,label):
 guard(self.out/(label+'-host-before.txt'))
 result=original(self,work,close,concurrency,duration,label)
 guard(self.out/(label+'-host-after.txt'))
 return result
m.Harness.wrk=wrk
sys.exit(m.main())
