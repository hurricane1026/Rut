import sys
sys.path.insert(0,'/home/hurricane/private/code/Rut-s1/scripts/ebpf_trace')
import trace
original=trace.generate
trace.GROUPS+=('copy-interrupt',)
def generate(*args):
 return original(*args)+'''
fentry:tcp_recvmsg /@targets[pid]/ {
 if (bswap(args.sk->__sk_common.skc_dport)==9987) { @ci_recv[tid]=1; }
}
fexit:tcp_recvmsg /@ci_recv[tid]/ { $ignored=delete(@ci_recv[tid]); }
fentry:skb_copy_datagram_iter /@ci_recv[tid]/ {
 @ci_start[tid]=nsecs; @ci_len[tid]=args.len;
}
fexit:skb_copy_datagram_iter /@ci_start[tid]/ {
 @ci_calls[pid]=count();
 @ci_wall_ns[pid]=sum((uint64)((int64)nsecs-(int64)@ci_start[tid]));
 if (retval==0) { @ci_bytes[pid]=sum(@ci_len[tid]); }
 else { @ci_errors[pid]=count(); }
 $ignored=delete(@ci_start[tid]); $ignored=delete(@ci_len[tid]);
}
tracepoint:irq:softirq_entry /@ci_start[tid]/ { @ci_soft_start[tid,args.vec]=nsecs; }
tracepoint:irq:softirq_exit /@ci_soft_start[tid,args.vec]/ {
 @ci_soft_ns[pid]=sum((uint64)((int64)nsecs-(int64)@ci_soft_start[tid,args.vec]));
 @ci_soft_calls[pid,args.vec]=count();
 $ignored=delete(@ci_soft_start[tid,args.vec]);
}
tracepoint:irq:irq_handler_entry /@ci_start[tid]/ { @ci_hard_start[tid,args.irq]=nsecs; }
tracepoint:irq:irq_handler_exit /@ci_hard_start[tid,args.irq]/ {
 @ci_hard_ns[pid]=sum((uint64)((int64)nsecs-(int64)@ci_hard_start[tid,args.irq]));
 @ci_hard_calls[pid]=count();
 $ignored=delete(@ci_hard_start[tid,args.irq]);
}
rawtracepoint:sched_switch {
 $prev=(struct task_struct*)arg1; $next=(struct task_struct*)arg2;
 if (@ci_start[$prev->pid]) { @ci_off_start[$prev->pid]=nsecs; }
 if (@ci_off_start[$next->pid]) {
  @ci_off_ns[$next->tgid]=sum((uint64)((int64)nsecs-(int64)@ci_off_start[$next->pid]));
  @ci_off_calls[$next->tgid]=count();
  $ignored=delete(@ci_off_start[$next->pid]);
 }
}
END { clear(@ci_recv); clear(@ci_start); clear(@ci_len); clear(@ci_soft_start); clear(@ci_hard_start); clear(@ci_off_start); }
'''
trace.generate=generate
sys.exit(trace.main())
