import sys
sys.path.insert(0,'/home/hurricane/private/code/Rut-s1/scripts/ebpf_trace')
import trace
original=trace.generate
trace.GROUPS=trace.GROUPS+('proxy-phases',)
def generate(*args):
 s=original(*args)
 return s+'''
// Entry/exit gaps include scheduling, network and origin work; not CPU time.
fentry:tcp_sendmsg /@targets[pid]/ {
 $sk=args.sk;
 if (bswap($sk->__sk_common.skc_dport)==9987) {
  @phase_sent[(uint64)$sk]=nsecs;
  if (@phase_front_read[pid]) {
   $gap=(uint64)((int64)nsecs-(int64)@phase_front_read[pid]);
   @front_read_to_upstream_send_ns[pid]=sum($gap);
   @front_read_to_upstream_send_count[pid]=count();
  }
 }
 if ($sk->__sk_common.skc_num==8987 && @phase_front_read[pid]) {
  $gap=(uint64)((int64)nsecs-(int64)@phase_front_read[pid]);
  @front_read_to_front_send_ns[pid]=sum($gap);
  @front_read_to_front_send_count[pid]=count();
  if (@phase_upstream_read[pid]) {
   $post=(uint64)((int64)nsecs-(int64)@phase_upstream_read[pid]);
   @upstream_read_to_front_send_ns[pid]=sum($post);
   @upstream_read_to_front_send_count[pid]=count();
  }
  $ignored=delete(@phase_front_read[pid]);
  $ignored=delete(@phase_upstream_read[pid]);
 }
}
fexit:tcp_recvmsg /@targets[pid] && retval > 0/ {
 $sk=args.sk;
 if ($sk->__sk_common.skc_num==8987) { @phase_front_read[pid]=nsecs; }
 if (bswap($sk->__sk_common.skc_dport)==9987 && @phase_sent[(uint64)$sk]) {
  $delta=(uint64)((int64)nsecs-(int64)@phase_sent[(uint64)$sk]);
  @phase_upstream_read[pid]=nsecs;
  @upstream_send_to_read_ns[pid]=sum($delta);
  @upstream_send_to_read_count[pid]=count();
  @upstream_send_to_read_us[pid]=hist($delta/1000);
  $ignored = delete(@phase_sent[(uint64)$sk]);
 }
}
fentry:tcp_close /@targets[pid]/ { $ignored = delete(@phase_sent[(uint64)args.sk]); }
END { clear(@phase_sent); clear(@phase_front_read); clear(@phase_upstream_read); }
'''
trace.generate=generate
sys.exit(trace.main())
