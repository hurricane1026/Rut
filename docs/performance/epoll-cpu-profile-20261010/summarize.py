import json,pathlib,re,collections,sys
root=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else '/tmp/rut-cpu-profile/final'); result={}
for p in root.glob('*.syscalls.jsonl'):
 maps={}
 for l in p.read_text().splitlines():
  d=json.loads(l)
  if d['type']=='map': maps.update(d['data'])
 if '@mode' not in maps:continue
 u=collections.Counter();k=collections.Counter();categories=collections.Counter(); firewall=0
 for key,n in maps.get('@user',{}).items():
  fn=key.split('\n')[1] if '\n' in key else key
  u[re.sub(r'\+\d+$','',fn)]+=n
 for key,n in maps.get('@kernel',{}).items():
  frames=key.split('\n')[1:];
  if any('nft_' in f or 'nf_conntrack' in f or 'nf_hook' in f for f in frames): firewall+=n
  k[re.sub(r'\+\d+$','',frames[0])]+=n
  cat='send' if any('tcp_sendmsg' in f for f in frames) else 'recv' if any('tcp_recvmsg' in f for f in frames) else 'epoll' if any('ep_' in f or 'epoll' in f for f in frames) else 'other'
  categories[cat]+=n
 out={'mode':maps['@mode'],'top_user':u.most_common(25),'top_kernel':k.most_common(20),'kernel_stack_categories':dict(categories),'firewall_inclusive_samples':firewall,'samples':sum(maps['@mode'].values())}
 result[p.name]=out
 print(p.name,json.dumps(out,ensure_ascii=False,indent=2))
(root/'profile-summary.json').write_text(json.dumps(result,indent=2))
