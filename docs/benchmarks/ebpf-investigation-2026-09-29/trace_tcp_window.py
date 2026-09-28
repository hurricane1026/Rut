import sys
sys.path.insert(0,'/home/hurricane/private/code/Rut-s1/scripts/ebpf_trace')
import trace
original=trace.generate
def generate(*args):
 s=original(*args)
 needle='@tcp_requested_bytes[pid, 2, $side] = sum(args.size);'
 assert needle in s
 return s.replace(needle,needle+'''
    if ($side == 1) {
        $tcp = (struct tcp_sock *)args.sk;
        @send_cwnd[pid] = hist($tcp->snd_cwnd);
        @send_peer_window[pid] = hist($tcp->snd_wnd);
        @send_notsent[pid] = hist((uint32)($tcp->write_seq - $tcp->snd_nxt));
        @send_packets_out[pid] = hist($tcp->packets_out);
        @send_socket_buffer[pid] = hist(args.sk->sk_sndbuf);
        @send_queued_memory[pid] = hist(args.sk->sk_wmem_queued);
        @send_flags[pid, args.msg->msg_flags] = count();
    }
''')
trace.generate=generate
sys.exit(trace.main())
