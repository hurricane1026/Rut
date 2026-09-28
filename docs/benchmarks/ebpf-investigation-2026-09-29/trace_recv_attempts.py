import sys
sys.path.insert(0,'/home/hurricane/private/code/Rut-s1/scripts/ebpf_trace')
import trace
original=trace.generate
trace.GROUPS=trace.GROUPS+('recv-attempts',)
def generate(*args):
 return original(*args)+"""
fentry:tcp_recvmsg /@targets[pid]/ {
 if (bswap(args.sk->__sk_common.skc_dport)==9987) { @recv_start[tid]=nsecs; }
}
fexit:tcp_recvmsg /@targets[pid] && @recv_start[tid]/ {
 $kind=retval > 0 ? 1 : (retval == -11 ? 2 : 3);
 @recv_attempts[pid,args.len,$kind]=count();
 @recv_elapsed_ns[pid,args.len,$kind]=sum((uint64)((int64)nsecs-(int64)@recv_start[tid]));
 if (retval>0) { @recv_bytes[pid,args.len]=sum((uint64)retval); }
 $ignored=delete(@recv_start[tid]);
}
END { clear(@recv_start); }
"""
trace.generate=generate
sys.exit(trace.main())
