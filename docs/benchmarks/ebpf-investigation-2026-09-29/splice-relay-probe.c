#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"line %d: %s errno=%d\n",__LINE__,#x,errno); exit(1); } } while (0)
static volatile sig_atomic_t gates;
static void gate_signal(int signum) { (void)signum; ++gates; }
static void pin(int cpu) { cpu_set_t m; CPU_ZERO(&m); CPU_SET(cpu,&m); CHECK(sched_setaffinity(0,sizeof(m),&m)==0); }
static double now(void) { struct timespec t; CHECK(clock_gettime(CLOCK_MONOTONIC,&t)==0); return t.tv_sec+t.tv_nsec/1e9; }
static double cpu(void) { struct rusage r; CHECK(getrusage(RUSAGE_SELF,&r)==0); return r.ru_utime.tv_sec+r.ru_stime.tv_sec+(r.ru_utime.tv_usec+r.ru_stime.tv_usec)/1e6; }
static int listener(struct sockaddr_in *a) { int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(fd>=0); *a=(struct sockaddr_in){.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)}; CHECK(bind(fd,(void*)a,sizeof(*a))==0); CHECK(listen(fd,1)==0); socklen_t n=sizeof(*a); CHECK(getsockname(fd,(void*)a,&n)==0); return fd; }
struct ring { int fd; char *sq,*cq; struct io_uring_sqe *sqes; struct io_uring_params p; };
static void ring_init(struct ring *r) {
 r->p=(struct io_uring_params){.flags=IORING_SETUP_COOP_TASKRUN|IORING_SETUP_TASKRUN_FLAG};
 r->fd=syscall(__NR_io_uring_setup,8,&r->p); CHECK(r->fd>=0);
 r->sq=mmap(NULL,r->p.sq_off.array+r->p.sq_entries*sizeof(unsigned),PROT_READ|PROT_WRITE,MAP_SHARED,r->fd,IORING_OFF_SQ_RING);
 r->cq=mmap(NULL,r->p.cq_off.cqes+r->p.cq_entries*sizeof(struct io_uring_cqe),PROT_READ|PROT_WRITE,MAP_SHARED,r->fd,IORING_OFF_CQ_RING);
 r->sqes=mmap(NULL,r->p.sq_entries*sizeof(*r->sqes),PROT_READ|PROT_WRITE,MAP_SHARED,r->fd,IORING_OFF_SQES);
 CHECK(r->sq!=MAP_FAILED && r->cq!=MAP_FAILED && r->sqes!=MAP_FAILED);
 cpu_set_t m; CPU_ZERO(&m); CPU_SET(2,&m);
 CHECK(syscall(__NR_io_uring_register,r->fd,IORING_REGISTER_IOWQ_AFF,&m,sizeof(m))==0);
}
static ssize_t move(struct ring *r,int in,int out,unsigned len,int uring) {
 if (!uring) return splice(in,NULL,out,NULL,len,SPLICE_F_MOVE);
 unsigned *tail=(void*)(r->sq+r->p.sq_off.tail), *mask=(void*)(r->sq+r->p.sq_off.ring_mask), *array=(void*)(r->sq+r->p.sq_off.array);
 unsigned index=__atomic_load_n(tail,__ATOMIC_RELAXED)&*mask;
 struct io_uring_sqe *e=&r->sqes[index]; memset(e,0,sizeof(*e));
 e->opcode=IORING_OP_SPLICE; e->fd=out; e->splice_fd_in=in; e->splice_off_in=-1; e->off=-1; e->len=len; e->splice_flags=SPLICE_F_MOVE; e->user_data=1;
 array[index]=index; __atomic_store_n(tail,*tail+1,__ATOMIC_RELEASE);
 CHECK(syscall(__NR_io_uring_enter,r->fd,1,1,IORING_ENTER_GETEVENTS,NULL,0)==1);
 unsigned *head=(void*)(r->cq+r->p.cq_off.head), *ctail=(void*)(r->cq+r->p.cq_off.tail), *cmask=(void*)(r->cq+r->p.cq_off.ring_mask);
 while (__atomic_load_n(head,__ATOMIC_RELAXED)==__atomic_load_n(ctail,__ATOMIC_ACQUIRE)) CHECK(syscall(__NR_io_uring_enter,r->fd,0,1,IORING_ENTER_GETEVENTS,NULL,0)>=0);
 struct io_uring_cqe *entries=(void*)(r->cq+r->p.cq_off.cqes); struct io_uring_cqe event=entries[*head&*cmask];
 CHECK(event.user_data==1 && event.flags==0); __atomic_store_n(head,*head+1,__ATOMIC_RELEASE); return event.res;
}
int main(int argc,char **argv) {
 CHECK(argc==2 || argc==4); int mode=!strcmp(argv[1],"copy")?0:!strcmp(argv[1],"splice")?1:!strcmp(argv[1],"uring-splice")?2:-1; CHECK(mode>=0);
 alarm(120); signal(SIGPIPE,SIG_IGN);
 const unsigned block=1048576, chunk=524288; const uint64_t warm=8ULL*block, measured=(argc==4?strtoull(argv[2],NULL,10):4096ULL)*block,total=warm+measured;
 int mem=memfd_create("splice-probe",MFD_CLOEXEC); CHECK(mem>=0 && ftruncate(mem,block)==0);
 unsigned char *pattern=mmap(NULL,block,PROT_READ|PROT_WRITE,MAP_SHARED,mem,0); CHECK(pattern!=MAP_FAILED); memset(pattern,0x5a,block);
 struct sockaddr_in origin_addr,client_addr; int ol=listener(&origin_addr), dl=listener(&client_addr);
 pid_t origin=fork(); CHECK(origin>=0);
 if (!origin) {
  alarm(120); pin(3); close(dl); int fd=accept4(ol,NULL,NULL,SOCK_CLOEXEC); CHECK(fd>=0); close(ol);
  uint64_t sent=0; while (sent<total) { off_t off=0; while (off<block) { ssize_t n=sendfile(fd,mem,&off,block-off); CHECK(n>0); sent+=(uint64_t)n; } }
  close(fd); _exit(0);
 }
 pid_t client=fork(); CHECK(client>=0);
 if (!client) {
  alarm(120); pin(4); close(ol); close(dl); int fd=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(fd>=0 && connect(fd,(void*)&client_addr,sizeof(client_addr))==0);
  unsigned char buffer[65536]; uint64_t got=0;
  while (got<total) { ssize_t n=read(fd,buffer,sizeof(buffer)); CHECK(n>0 && memcmp(buffer,pattern,n)==0); got+=(uint64_t)n; }
  CHECK(got==total); close(fd); _exit(0);
 }
 pin(2); close(ol); int up=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0); CHECK(up>=0 && connect(up,(void*)&origin_addr,sizeof(origin_addr))==0);
 int down=accept4(dl,NULL,NULL,SOCK_CLOEXEC); CHECK(down>=0); close(dl);
 int pipes[2]={-1,-1},pipe_capacity=0; struct ring r={0};
 if (mode) { CHECK(pipe2(pipes,O_CLOEXEC)==0); pipe_capacity=fcntl(pipes[0],F_SETPIPE_SZ,chunk); CHECK(pipe_capacity>0); }
 if (mode==2) ring_init(&r);
 unsigned char *buffer=mmap(NULL,chunk,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); CHECK(buffer!=MAP_FAILED);
 sigset_t gate_mask, original_mask;
 if (argc==4) {
  sigemptyset(&gate_mask); sigaddset(&gate_mask,SIGUSR1); CHECK(sigprocmask(SIG_BLOCK,&gate_mask,&original_mask)==0);
  CHECK(signal(SIGUSR1,gate_signal)!=SIG_ERR);
  printf("{\"ready\":true,\"pid\":%d}\n",getpid()); fflush(stdout);
  while (gates<1) sigsuspend(&original_mask);
 }
 uint64_t forwarded=0,calls_in=0,calls_out=0; double start=0,cpu_start=0;
 while (forwarded<total) {
  uint64_t left=forwarded<warm?warm-forwarded:total-forwarded; unsigned requested=left<chunk?(unsigned)left:chunk;
  ssize_t n=mode?move(&r,up,pipes[1],requested,mode==2):recv(up,buffer,requested,0); CHECK(n>0);
  if (forwarded>=warm) ++calls_in;
  unsigned done=0; while (done<(unsigned)n) { ssize_t w=mode?move(&r,pipes[0],down,(unsigned)n-done,mode==2):send(down,buffer+done,(unsigned)n-done,MSG_NOSIGNAL); CHECK(w>0); done+=(unsigned)w; if (forwarded>=warm) ++calls_out; }
  forwarded+=(uint64_t)n;
  if (forwarded==warm) { cpu_start=cpu(); start=now(); }
 }
 close(up); close(down); int a,b; CHECK(waitpid(origin,&a,0)==origin && WIFEXITED(a) && WEXITSTATUS(a)==0); CHECK(waitpid(client,&b,0)==client && WIFEXITED(b) && WEXITSTATUS(b)==0);
 double seconds=now()-start,cpu_seconds=cpu()-cpu_start;
 printf("{\"mode\":\"%s\",\"bytes\":%llu,\"seconds\":%.6f,\"relay_cpu_seconds\":%.6f,\"gib_per_second\":%.6f,\"in_calls\":%llu,\"out_calls\":%llu,\"pipe_capacity\":%d,\"body_verified\":true,\"worker_affinity_cpu\":2}\n",argv[1],(unsigned long long)measured,seconds,cpu_seconds,measured/seconds/1073741824.0,(unsigned long long)calls_in,(unsigned long long)calls_out,pipe_capacity);
 fflush(stdout);
 if (argc==4) { while (gates<2) sigsuspend(&original_mask); }
 return 0;
}
