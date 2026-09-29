import sys
sys.path.insert(0,'/home/hurricane/private/code/Rut-s1/scripts/ebpf_trace')
import trace
original=trace.generate
trace.GROUPS+=('copy-reuse',)
def generate(*args):
 return 'config = { max_map_keys = 65536; }\n'+original(*args)+'''
fentry:tcp_recvmsg /@targets[pid]/ {
 if (bswap(args.sk->__sk_common.skc_dport)==9987) { @cr_recv[tid]=1; }
}
fexit:tcp_recvmsg /@cr_recv[tid]/ { $ignored=delete(@cr_recv[tid]); }
fentry:skb_copy_datagram_iter /@cr_recv[tid]/ {
 $it=args.to;
 @cr_types[pid,$it->iter_type]=count();
 if ($it->iter_type==0 || $it->iter_type==1) {
  $dst=(uint64)$it->ubuf;
  if ($it->iter_type==1) { $dst=(uint64)$it->__iov->iov_base; }
  $region=($dst+$it->iov_offset)>>14;
  $now=nsecs;
  $last=@cr_last[pid,$region];
  $bucket=(uint64)5;
  if ($last) {
   $age=(uint64)((int64)$now-(int64)$last);
   @cr_age_us[pid]=hist($age/1000);
   $bucket=4;
   if ($age<10000000) { $bucket=3; }
   if ($age<1000000) { $bucket=2; }
   if ($age<100000) { $bucket=1; }
   if ($age<10000) { $bucket=0; }
  } else { @cr_unique_regions[pid]=count(); }
  @cr_last[pid,$region]=$now;
  @cr_calls[pid,$bucket]=count();
  @cr_bytes[pid,$bucket]=sum(args.len);
  $epoch=$now/100000000;
  if (@cr_epoch[pid,$region]!=$epoch) {
   @cr_epoch[pid,$region]=$epoch;
   @cr_window_regions[pid,$epoch]=count();
  }
 } else { @cr_unsupported[pid]=count(); }
}
END { clear(@cr_recv); clear(@cr_last); clear(@cr_epoch); }
'''
trace.generate=generate
sys.exit(trace.main())
