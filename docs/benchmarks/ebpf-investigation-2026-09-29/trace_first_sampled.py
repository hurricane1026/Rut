import sys
sys.path.insert(0, '/home/hurricane/private/code/Rut-s1/scripts/ebpf_trace')
import trace
original=trace.generate
trace.GROUPS+=('first-sampled',)
def generate(*args):
 return original(*args)+'''
// c1 only. Random 1/64 front requests, emit at first downstream send.
fexit:tcp_recvmsg /@targets[pid] && retval>0/ {
 if (args.sk->__sk_common.skc_num==8987) {
  $ignored=delete(@first_start[pid]);
  $ignored=delete(@first_upsend[pid]);
  $ignored=delete(@first_uprecv[pid]);
  if ((rand & 63)==0) { @first_start[pid]=nsecs; }
 } else if (@first_start[pid] && bswap(args.sk->__sk_common.skc_dport)==9987 && !@first_uprecv[pid]) {
  @first_uprecv[pid]=nsecs;
 }
}
fentry:tcp_sendmsg /@targets[pid] && @first_start[pid]/ {
 if (bswap(args.sk->__sk_common.skc_dport)==9987 && !@first_upsend[pid]) {
  @first_upsend[pid]=nsecs;
 } else if (args.sk->__sk_common.skc_num==8987) {
  $now=nsecs;
  if (@first_upsend[pid] && @first_uprecv[pid]) {
   @first_requests[pid]=count();
   @first_request_ns[pid]=sum((uint64)((int64)@first_upsend[pid]-(int64)@first_start[pid]));
   @first_origin_ns[pid]=sum((uint64)((int64)@first_uprecv[pid]-(int64)@first_upsend[pid]));
   @first_response_ns[pid]=sum((uint64)((int64)$now-(int64)@first_uprecv[pid]));
   @first_total_ns[pid]=sum((uint64)((int64)$now-(int64)@first_start[pid]));
  } else { @first_incomplete[pid]=count(); }
  $ignored=delete(@first_start[pid]);
  $ignored=delete(@first_upsend[pid]);
  $ignored=delete(@first_uprecv[pid]);
 }
}
END { clear(@first_start); clear(@first_upsend); clear(@first_uprecv); }
'''
trace.generate=generate
sys.exit(trace.main())
