import sys
sys.path.insert(0,'/home/hurricane/private/code/Rut-s1/scripts/ebpf_trace')
import trace
original=trace.generate
trace.GROUPS=trace.GROUPS+('final-send-fin',)
def generate(*args):
 return original(*args)+'''
tracepoint:syscalls:sys_enter_shutdown /@targets[pid]/ { @shutdown_syscalls[pid]=count(); }
fentry:tcp_sendmsg /@targets[pid]/ {
 $sk=args.sk;
 if ($sk->__sk_common.skc_num==8987) {
  @final_send_started[(uint64)$sk]=nsecs;
  @final_send_calls[pid]=count();
 }
}
fentry:tcp_shutdown /@targets[pid]/ {
 $sk=args.sk;
 if ($sk->__sk_common.skc_num==8987) { @shutdown_calls[pid]=count(); @shutdown_started[tid]=nsecs; }
 if ($sk->__sk_common.skc_num==8987 && @final_send_started[(uint64)$sk]) {
  $delta=(uint64)((int64)nsecs-(int64)@final_send_started[(uint64)$sk]);
  @send_to_shutdown_ns[pid]=sum($delta);
  @send_to_shutdown_count[pid]=count();
  @send_to_shutdown_us[pid]=hist($delta/1000);
  $ignored=delete(@final_send_started[(uint64)$sk]);
 }
}
fexit:tcp_shutdown /@targets[pid] && @shutdown_started[tid]/ {
 $delta=(uint64)((int64)nsecs-(int64)@shutdown_started[tid]);
 @shutdown_ns[pid]=sum($delta);
 @shutdown_us[pid]=hist($delta/1000);
 $ignored=delete(@shutdown_started[tid]);
}
fentry:tcp_close /@targets[pid]/ { $ignored=delete(@final_send_started[(uint64)args.sk]); }
END { clear(@final_send_started); clear(@shutdown_started); }
'''
trace.generate=generate
sys.exit(trace.main())
