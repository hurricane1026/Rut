#include "fixture_collision_release_evidence_protocol.h"

#include <cassert>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <limits>
#include <vector>

namespace p = rut::test::fixture_collision_release_evidence_protocol;
namespace w = rut::test::fixture_worker_protocol;
using u64 = w::u64;

static w::Token token() { w::Token t{}; for (std::size_t i=0;i<t.bytes.size();++i) t.bytes[i]=static_cast<unsigned char>(i+3); return t; }
static void put(std::vector<unsigned char>& b,u64 v) { for(unsigned s=0;s<64;s+=8)b.push_back(static_cast<unsigned char>(v>>s)); }
static std::string cmdline(const std::string& path="/tmp/source",std::size_t total=0) {
    std::string a0="/bin/rut"; const char* fixed[]={"--shards","1","--no-pin","--drain","0","--opt","2"};
    std::size_t base=a0.size()+1+path.size()+1; for(const char* s:fixed) base+=std::strlen(s)+1;
    if(total) a0.append(total-base,'x');
    std::string s=a0; s.push_back('\0'); s+=path; s.push_back('\0'); for(const char* x:fixed){s+=x;s.push_back('\0');} return s;
}
static p::Envelope env(p::ReportKind k,p::Binding b,p::Phase ph,u64 seq) { p::Envelope e; e.transaction=0x37759;e.kind=k;e.binding=b;e.phase=ph;e.sequence=seq;e.target={77,991,55};return e; }
static p::ReservationSource source() { p::ReservationSource x; x.reservation_state=1;x.g_fd=12;x.g_f_getfd=1;x.g_f_getfl=2;x.ipv4=0x7f000001;x.port=34567;x.dev=22;x.ino=123456;x.mode=0140000;x.rdev=0;x.socket_domain=2;x.socket_type=1;x.socket_protocol=6;x.reuseaddr=1;x.reuseport=1;x.acceptconn=0;x.proc_link="socket:[123456]";x.proc_link_len=x.proc_link.size();x.directory_dev=22;x.directory_ino=77;x.directory_mode=01777;x.directory_uid=1000;x.directory_gid=1000;x.source_state=1;x.source_dev=33;x.source_ino=44;x.source_mode=0100600;x.source_uid=1000;x.source_gid=1000;x.source_size=32;x.source_nlink=1;x.source_path="/tmp/source";x.source_bytes.assign(32,'s');x.path_len=x.source_path.size();x.bytes_len=x.source_bytes.size();return x; }
static p::Cleanup14 cleanup() { p::Cleanup14 x; x.destructor_attempted=x.destructor_reportable_success=x.child_attempted=x.child_settled=x.handoff_attempted=x.handoff_closed=x.null_attempted=x.null_closed=x.capture_settle_attempted=x.capture_settled=x.capture_close_attempted=x.capture_closed=1; return x; }
static p::ProcPair procs(u64 pid,u64 start) { p::ProcPair x; x.first_tag=x.second_tag=1;x.first={pid,77,1,start,1,1000,1000,55,2,3,1,1,0};x.second=x.first;return x; }
static p::Settlement9 exited(u64 pid,u64 start) { return {pid,pid,77,start,55,1,1,256,0}; }
static p::CollisionAttempt collision(const p::ReservationSource& s,bool live) { p::CollisionAttempt x; x.cross={s.g_fd,s.ino,s.source_dev,s.source_ino};x.header={live?2u:1u,1,98,88,1000,live?2u:1u,cmdline(s.source_path).size()};x.procs=live?procs(88,1000):p::ProcPair{};x.settlement=exited(88,1000);x.cleanup=cleanup();x.classifier={1,2,98,4,9};x.cmdline=cmdline(s.source_path);return x; }

static void golden() {
    const auto t=token(); const p::Envelope e=env(p::ReportKind::CollisionCapture,p::Binding::Phase,p::Phase::CollisionNaturallyRejectedEvidenceOpen,3);
    std::vector<unsigned char> payload; for(u64 v:{2,0x37759,1,3,1,2,3,77,991,55,11})put(payload,v); put(payload,3); payload.insert(payload.end(),{'a','b','c'});
    w::Frame f{59,t,payload}; p::CollisionCapture out; assert(p::decode_collision_capture(f,t,e,out)); assert(out.capture_len==3&&out.capture=="abc");
    // The payload is assembled independently of the encoder; every envelope word is LE u64.
    auto encoded=p::encode_collision_capture(t,e,out); assert(encoded.payload==payload);
    payload[88]=4; assert(!p::decode_collision_capture({59,t,payload},t,e,out));
}
static void maxima() {
    const auto t=token(); auto s=source(); s.proc_link.assign(p::kMaxProcLink,'x');s.proc_link[0]='s';s.proc_link[1]='o';s.proc_link[2]='c';s.proc_link[3]='k';s.proc_link[4]='e';s.proc_link[5]='t';s.proc_link[6]=':';s.proc_link[7]='[';s.proc_link.back()=']';s.proc_link_len=s.proc_link.size();s.source_path.assign(p::kMaxSourcePath,'p');s.source_bytes.assign(p::kMaxSourceBytes,'b');s.path_len=s.source_path.size();s.bytes_len=s.source_bytes.size(); assert(p::encode_reservation_source(t,env(p::ReportKind::ReservationSource,p::Binding::Phase,p::Phase::ReservationHeld,1),s).payload.size()==p::kReservationSourceMax);
    auto c=collision(s,false); c.cmdline=cmdline(s.source_path,p::kMaxCmdline);c.header.cmdline_len=c.cmdline.size(); assert(p::encode_collision_attempt(t,env(p::ReportKind::CollisionAttempt,p::Binding::Phase,p::Phase::CollisionNaturallyRejectedEvidenceOpen,3),c).payload.size()==p::kCollisionAttemptMax);
    p::CollisionCapture cap{p::kMaxCapture,std::string(p::kMaxCapture,'c')}; assert(p::encode_collision_capture(t,env(p::ReportKind::CollisionCapture,p::Binding::Phase,p::Phase::CollisionNaturallyRejectedEvidenceOpen,3),cap).payload.size()==p::kCollisionCaptureMax);
    p::EvidenceClosed ec; assert(p::encode_evidence_closed(t,env(p::ReportKind::EvidenceClosed,p::Binding::Phase,p::Phase::EvidenceClosedReservationHeld,5),ec).payload.size()==p::kEvidenceClosedMax);
    p::Release rel; assert(p::encode_release(t,env(p::ReportKind::Release,p::Binding::Phase,p::Phase::ReservationReleased,7),rel).payload.size()==p::kReleaseMax);
    p::RetryLive rl; rl.source_path.assign(p::kMaxSourcePath,'p');rl.source_path_len=rl.source_path.size();rl.cmdline=cmdline(rl.source_path,p::kMaxCmdline);rl.header.cmdline_len=rl.cmdline.size(); assert(p::encode_retry_live(t,env(p::ReportKind::RetryLive,p::Binding::Phase,p::Phase::RetryLive,9),rl).payload.size()==p::kRetryLiveMax);
    assert(p::encode_retry_live_capture(t,env(p::ReportKind::RetryLiveCapture,p::Binding::Phase,p::Phase::RetryLive,9),{p::kMaxCapture,std::string(p::kMaxCapture,'x')}).payload.size()==p::kRetryLiveCaptureMax);
    p::RetrySettlement rs; assert(p::encode_retry_settlement(t,env(p::ReportKind::RetrySettlement,p::Binding::Settlement,p::Phase::RetryLive,11),rs).payload.size()==p::kRetrySettlementMax);
    assert(p::encode_retry_final_capture(t,env(p::ReportKind::RetryFinalCapture,p::Binding::Settlement,p::Phase::RetryLive,11),{p::kMaxCapture,std::string(p::kMaxCapture,'x')}).payload.size()==p::kRetryFinalCaptureMax);
}

static void transcript(bool live) {
    const auto t=token(); const auto s=source(); p::ReceiverContext c; c.token=t;c.transaction=0x37759;c.target={77,991,55};c.expected_source=s;c.expected_cmdline=cmdline(s.source_path); p::Receiver r(c);
    assert(r.observe(p::encode_reservation_source(t,env(p::ReportKind::ReservationSource,p::Binding::Phase,p::Phase::ReservationHeld,1),s)));
    auto ca=collision(s,live); assert(r.observe(p::encode_collision_attempt(t,env(p::ReportKind::CollisionAttempt,p::Binding::Phase,p::Phase::CollisionNaturallyRejectedEvidenceOpen,3),ca)));
    assert(r.observe(p::encode_collision_capture(t,env(p::ReportKind::CollisionCapture,p::Binding::Phase,p::Phase::CollisionNaturallyRejectedEvidenceOpen,3),{9,"collision"})));
    p::EvidenceClosed ec;ec.g_fd=s.g_fd;ec.g_inode=s.ino;ec.source_dev=s.source_dev;ec.source_inode=s.source_ino;ec.child_pid=ca.header.child_pid;ec.child_start=ca.header.child_start;ec.attempt_state=ca.header.attempt_state;ec.reservation_state=1;ec.source_state=1;ec.capture_len=9;ec.cleanup=cleanup(); assert(r.observe(p::encode_evidence_closed(t,env(p::ReportKind::EvidenceClosed,p::Binding::Phase,p::Phase::EvidenceClosedReservationHeld,5),ec)));
    p::Release rel;rel={s.g_fd,s.ipv4,s.port,s.ino,{1,0,1,0,0,0,std::numeric_limits<u64>::max(),9,1,1,1,1,1,4,0,0}}; assert(r.observe(p::encode_release(t,env(p::ReportKind::Release,p::Binding::Phase,p::Phase::ReservationReleased,7),rel)));
    p::RetryLive rl;rl.source_dev=s.source_dev;rl.source_inode=s.source_ino;rl.source_size=s.source_size;rl.source_path=s.source_path;rl.source_path_len=rl.source_path.size();rl.g_inode=s.ino;rl.port=s.port;rl.header={2,1,98,99,1999,2,cmdline(s.source_path).size()};rl.procs=procs(99,1999);rl.pidfd={4,1,1,99};rl.startup={1,2,s.port,6};rl.cmdline=cmdline(s.source_path); assert(r.observe(p::encode_retry_live(t,env(p::ReportKind::RetryLive,p::Binding::Phase,p::Phase::RetryLive,9),rl)));
    assert(r.observe(p::encode_retry_live_capture(t,env(p::ReportKind::RetryLiveCapture,p::Binding::Phase,p::Phase::RetryLive,9),{6,"prefix"})));
    p::RetrySettlement rs{s.source_dev,s.source_ino,99,1999,2,{99,99,77,1999,55,1,1,9,0},cleanup(),12}; assert(r.observe(p::encode_retry_settlement(t,env(p::ReportKind::RetrySettlement,p::Binding::Settlement,p::Phase::RetryLive,11),rs)));
    assert(r.observe(p::encode_retry_final_capture(t,env(p::ReportKind::RetryFinalCapture,p::Binding::Settlement,p::Phase::RetryLive,11),{12,"prefix-final"}))); assert(r.finish()&&r.state()==p::State::Complete); assert(!r.observe({})); assert(r.state()==p::State::Failed);
}
static void rejection_matrix() {
    const auto t=token(); const auto s=source(); p::ReceiverContext c; c.token=t;c.transaction=0x37759;c.target={77,991,55};c.expected_source=s;c.expected_cmdline=cmdline(s.source_path);
    { p::Receiver r(c); auto f=p::encode_reservation_source(t,env(p::ReportKind::ReservationSource,p::Binding::Phase,p::Phase::ReservationHeld,1),s); f.payload[0]=3; assert(!r.observe(f)&&r.state()==p::State::Failed); assert(r.source()==p::ReservationSource{}); }
    { p::Receiver r(c); auto f=p::encode_reservation_source(t,env(p::ReportKind::ReservationSource,p::Binding::Phase,p::Phase::ReservationHeld,1),s); assert(r.observe(f)); auto f2=f; f2.payload[0]=2; assert(!r.observe(f2)&&r.state()==p::State::Failed&&r.source()==s); }
    { auto x=collision(s,false); x.procs.first_tag=2; auto f=p::encode_collision_attempt(t,env(p::ReportKind::CollisionAttempt,p::Binding::Phase,p::Phase::CollisionNaturallyRejectedEvidenceOpen,3),x); assert(f.type==59); p::CollisionAttempt out; assert(!p::decode_collision_attempt(f,t,env(p::ReportKind::CollisionAttempt,p::Binding::Phase,p::Phase::CollisionNaturallyRejectedEvidenceOpen,3),out)); }
    { p::Receiver r(c); assert(r.observe(p::encode_reservation_source(t,env(p::ReportKind::ReservationSource,p::Binding::Phase,p::Phase::ReservationHeld,1),s))); auto x=collision(s,false);x.cmdline[0]='X';x.header.cmdline_len=x.cmdline.size();assert(!r.observe(p::encode_collision_attempt(t,env(p::ReportKind::CollisionAttempt,p::Binding::Phase,p::Phase::CollisionNaturallyRejectedEvidenceOpen,3),x))); }
}
int main() { golden();maxima();transcript(false);transcript(true);rejection_matrix();std::cout<<"collision-release-evidence-ok\n"; }
