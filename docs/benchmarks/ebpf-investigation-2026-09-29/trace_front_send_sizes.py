import sys
sys.path.insert(0,'/home/hurricane/private/code/Rut-s1/scripts/ebpf_trace')
import trace
original=trace.generate
def generate(*args):
 return original(*args)+'''
fentry:tcp_sendmsg /@targets[pid]/ {
 $sk=args.sk;
 if ($sk->__sk_common.skc_num==8987) {
  @front_send_size[pid]=hist(args.size);
  @front_send_calls[pid]=count();
 }
}
'''
trace.generate=generate
sys.exit(trace.main())
