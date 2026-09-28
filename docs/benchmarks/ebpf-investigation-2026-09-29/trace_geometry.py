import sys
sys.path.insert(0,'/home/hurricane/private/code/Rut-s1/scripts/ebpf_trace')
import trace
original=trace.generate
def generate(*args):
 s=original(*args)
 s=s.replace('@copy_length[tid, 1] = args.len;', '''@copy_length[tid, 1] = args.len;
    $it = args.to;
    $dst = (uint64)$it->ubuf;
    if ($it->iter_type == 1) { $dst = (uint64)$it->__iov->iov_base; }
    @geom_type[tid] = (uint64)$it->iter_type;
    @geom_offset[tid] = ($dst + $it->iov_offset) & 4095;
    @geom_len[tid] = (uint64)args.len / 4096;
''')
 s=s.replace('@copy_calls[pid, 1, $side] = count();','''@copy_calls[pid, 1, $side] = count();
    if ($side == 2) {
        @geometry_calls[pid, @geom_type[tid], @geom_offset[tid], @geom_len[tid]] = count();
        @geometry_bytes[pid, @geom_type[tid], @geom_offset[tid], @geom_len[tid]] = sum(@copy_length[tid, 1]);
        @geometry_ns[pid, @geom_type[tid], @geom_offset[tid], @geom_len[tid]] = sum($ns);
    }
    $ignored = delete(@geom_type[tid]);
    $ignored = delete(@geom_offset[tid]);
    $ignored = delete(@geom_len[tid]);
''')
 s=s.replace('clear(@copy_length);','clear(@copy_length); clear(@geom_type); clear(@geom_offset); clear(@geom_len);')
 return s
trace.generate=generate
sys.exit(trace.main())
