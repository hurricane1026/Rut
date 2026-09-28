import json,sys
from pathlib import Path
root=Path(sys.argv[1]);rows=[]
for d in sorted(root.iterdir()):
 if not (d/'trace/summary.json').exists():continue
 s=json.loads((d/'trace/summary.json').read_text());m=s['maps'];status=json.loads((d/'trace/status.json').read_text())
 p=json.loads((d/'process.json').read_text());pid=str(p['pid'])
 metrics=[l.split()[1:] for l in (d/'wrk.log').read_text().splitlines() if l.startswith('METRICS ')][0]
 n=int(metrics[0]);seconds=int(metrics[1])/1e6
 row={'case':d.name,'requests':n,'rps_traced':n/seconds,'errors':list(map(int,metrics[5:])),'usable':status['usable']}
 a=p['before']['stat'].rsplit(')',1)[1].split();b=p['after']['stat'].rsplit(')',1)[1].split()
 for k,i in [('user_us',11),('system_us',12)]:row[k]=(int(b[i])-int(a[i]))*10000/n
 for k in ['minor_faults','runqueue_ns','offcpu_ns']:
  row[k+'_per_request']=(m.get('@'+k,{}).get(pid,0)/n if ('fault' if k == 'minor_faults' else 'sched') in status['groups'] else None)
 for r in s['tcp']:
  key=f"{r['side']}_{r['direction']}";row[key]={'calls_per_request':r['completed_calls']/n,'bytes_per_call':r['returned_bytes']/r['completed_calls'],'us_per_request':r['inclusive_elapsed_ns']/n/1000,'ns_per_byte':r['inclusive_elapsed_ns']/r['returned_bytes'] if r['returned_bytes'] else 0}
 for key,ns in m.get('@copy_elapsed_ns',{}).items():
  _,direction,side=map(int,key.split(','));bc=m.get('@copy_success_bytes',{}).get(key,0)
  row[f'copy_side_{side}']={'ns_per_byte':ns/bc if bc else 0,'us_per_request':ns/n/1000,'bytes_per_request':bc/n}
 rows.append(row)
 print(d.name,'rps',round(row['rps_traced']), 'usr/sys',round(row['user_us'],1),round(row['system_us'],1),'faults',(round(row['minor_faults_per_request'],3) if row['minor_faults_per_request'] is not None else None),'rq_us',(round(row['runqueue_ns_per_request']/1000,1) if row['runqueue_ns_per_request'] is not None else None),flush=True)
 for k,v in row.items():
  if isinstance(v,dict):print(' ',k,{a:round(b,3) for a,b in v.items()})
(root/'comparison.json').write_text(json.dumps(rows,indent=2)+'\n')
