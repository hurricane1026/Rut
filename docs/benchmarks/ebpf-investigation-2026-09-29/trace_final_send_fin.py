import sys
sys.path.insert(0,'/home/hurricane/private/code/Rut-s1/scripts/ebpf_trace')
import trace
original=trace.generate
trace.GROUPS=trace.GROUPS+('final-send-fin',)
def generate(*args):
 return original(*args)+'''
fentry:tcp_sendmsg /@targets[pid]/ {
 $sk=args.sk;
 if ($sk->__sk_common.skc_num==8987) {
  @final_send_started[(uint64)$sk]=nsecs;
  @final_send_calls[pid]=count();
 }
}
fentry:tcp_shutdown /@targets[pid]/ {
 $sk=args.sk;
 if ($sk->__sk_common.skc_num==8987 && @final_send_started[(uint64)$sk]) {
  $delta=(uint64)((int64)nsecs-(int64)@final_send_started[(uint64)$sk]);
  @send_to_shutdown_ns[pid]=sum($delta);
  @send_to_shutdown_count[pid]=count();
  @send_to_shutdown_us[pid]=hist($delta/1000);
  $ignored=delete(@final_send_started[(uint64)$sk]);
 }
}
fentry:tcp_close /@targets[pid]/ { $ignored=delete(@final_send_started[(uint64)args.sk]); }
END { clear(@final_send_started); }
'''
trace.generate=generate
sys.exit(trace.main())
