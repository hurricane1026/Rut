import sys
sys.path.insert(0,'/home/hurricane/private/code/Rut-s1/scripts/ebpf_trace')
import trace
original=trace.generate
trace.GROUPS+=('relay-copies',)
def generate(*args):
 return original(*args)+'''
fentry:skb_copy_datagram_iter /@targets[pid]/ {
 @relay_copy_calls[pid]=count();
 @relay_copy_bytes[pid]=sum(args.len);
}
fentry:tcp_splice_read /@targets[pid]/ { @relay_splice_read_calls[pid]=count(); }
fentry:splice_to_socket /@targets[pid]/ { @relay_splice_send_calls[pid]=count(); }
'''
trace.generate=generate
sys.exit(trace.main())
