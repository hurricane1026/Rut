from pathlib import Path
import json,sys,collections
for d in Path(sys.argv[1]).iterdir():
 p=d/'trace/summary.json'
 if not p.exists():continue
 m=json.loads(p.read_text())['maps'];byoff=collections.defaultdict(lambda:[0,0,0]);bysize=collections.defaultdict(lambda:[0,0,0])
 for k,n in m['@geometry_calls'].items():
  pid,t,off,size=map(int,k.split(','));b=m['@geometry_bytes'][k];ns=m['@geometry_ns'][k]
  if size==0:continue
  for group,index in [(byoff,off),(bysize,size)]:
   for i,v in enumerate([n,b,ns]):group[index][i]+=v
 print(d.name)
 for name,group in [('offset',byoff),('size',bysize)]:
  print(name)
  for k,v in sorted(group.items(),key=lambda x:x[1][1],reverse=True)[:20]:print(k,v[0],round(v[1]/1e6,1),round(v[2]/v[1],3))
