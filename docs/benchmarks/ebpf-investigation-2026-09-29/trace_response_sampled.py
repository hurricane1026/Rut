import sys
sys.path.insert(0, '/home/hurricane/private/code/Rut-s1/scripts/ebpf_trace')
import trace
original = trace.generate
trace.GROUPS += ('response-sampled',)
EMIT = '''
 if (@sample_start[$key] && @sample_last[$key]) {
  @sample_requests[pid]=count();
  @sample_total_ns[pid]=sum((uint64)((int64)@sample_last[$key]-(int64)@sample_start[$key]));
  @sample_first_ns[pid]=sum((uint64)((int64)@sample_first[$key]-(int64)@sample_start[$key]));
  @sample_tail_ns[pid]=sum((uint64)((int64)@sample_last[$key]-(int64)@sample_first[$key]));
  @sample_bytes[pid]=sum(@sample_bytes_current[$key]);
 }
 $ignored=delete(@sample_start[$key]);
 $ignored=delete(@sample_first[$key]);
 $ignored=delete(@sample_last[$key]);
 $ignored=delete(@sample_bytes_current[$key]);
'''
def generate(*args):
 return original(*args) + '''
// Random 1/64 downstream request sampling; c1/non-pipelined only.
fexit:tcp_recvmsg /@targets[pid] && retval>0/ {
 if (args.sk->__sk_common.skc_num==8987) {
  $key=(uint64)args.sk;
  if (@sample_start[$key]) { ''' + EMIT + ''' }
  if ((rand & 63)==0) { @sample_start[$key]=nsecs; }
 }
}
fentry:tcp_sendmsg /@targets[pid]/ {
 if (args.sk->__sk_common.skc_num==8987) {
  $key=(uint64)args.sk;
  if (@sample_start[$key] && !@sample_first[$key]) { @sample_first[$key]=nsecs; }
 }
}
fexit:tcp_sendmsg /@targets[pid] && retval>0/ {
 if (args.sk->__sk_common.skc_num==8987) {
  $key=(uint64)args.sk;
  if (@sample_start[$key]) {
   @sample_last[$key]=nsecs;
   @sample_bytes_current[$key]=(uint64)((int64)@sample_bytes_current[$key]+(int64)retval);
  }
 }
}
fentry:tcp_close /@targets[pid]/ {
 if (args.sk->__sk_common.skc_num==8987) {
  $key=(uint64)args.sk;
  if (@sample_start[$key]) { ''' + EMIT + ''' }
 }
}
END { clear(@sample_start); clear(@sample_first); clear(@sample_last); clear(@sample_bytes_current); }
'''
trace.generate = generate
sys.exit(trace.main())
