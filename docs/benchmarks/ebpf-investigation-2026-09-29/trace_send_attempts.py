import sys
sys.path.insert(0,'/home/hurricane/private/code/Rut-s1/scripts/ebpf_trace')
import trace
original=trace.generate
trace.GROUPS+=('send-attempts',)
def generate(*args):
 return original(*args)+'''
fexit:tcp_sendmsg /@targets[pid]/ {
 if (args.sk->__sk_common.skc_num==8987) {
  $kind=retval>0 ? ((uint64)retval<args.size ? 2 : 1) : (retval==-11 ? 3 : 4);
  @send_attempts[pid,$kind]=count();
  @send_requested[pid,$kind]=sum(args.size);
  @send_lengths[pid,$kind]=hist(args.size);
  if (retval>0) { @send_bytes[pid]=sum((uint64)retval); }
 }
}
'''
trace.generate=generate
sys.exit(trace.main())
