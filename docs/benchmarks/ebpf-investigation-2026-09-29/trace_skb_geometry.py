import sys
sys.path.insert(0,'/home/hurricane/private/code/Rut-s1/scripts/ebpf_trace')
import trace
original=trace.generate
trace.GROUPS=trace.GROUPS+('skb-geometry',)
def generate(*args):
 s=original(*args)
 return s+'''
fentry:skb_copy_datagram_iter /@targets[pid] && ((rand & 63) == 0)/ {
    $skb = args.skb;
    $sh = (struct skb_shared_info *)((uint64)$skb->head + (uint64)$skb->end);
    @skb_geometry_samples[pid] = count();
    @skb_fragments[pid] = hist($sh->nr_frags);
    @skb_bytes[pid] = hist($skb->len);
    @skb_linear_bytes[pid] = hist($skb->len - $skb->data_len);
    @copy_requested_bytes[pid] = hist(args.len);
    @copy_offset[pid] = hist(args.offset);
    @skb_geometry[pid, $sh->nr_frags, (uint64)args.len / 4096] = count();
}
'''
trace.generate=generate
sys.exit(trace.main())
