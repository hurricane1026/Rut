#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <sys/types.h>

namespace rut::test::fixture_worker_protocol {

using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

constexpr u32 kMagic = 0x31523335u;
constexpr u16 kVersion = 1;
constexpr u16 kReady = 1;
constexpr u16 kPing = 2;
constexpr u16 kPong = 3;
constexpr u16 kRelease = 4;
constexpr u16 kReleased = 5;
constexpr size_t kTokenBytes = 32;
static_assert(kTokenBytes == 32);
constexpr size_t kHeaderBytes = 4 + 2 + 2 + 4 + kTokenBytes;
constexpr size_t kReportFixedBytes = 13 * sizeof(u64) + 4 * sizeof(u16);
constexpr size_t kMaxPayload = 8192;
constexpr int kHandshakeMs = 2500;
constexpr int kCleanupMs = 350;

struct Token {
    std::array<unsigned char, kTokenBytes> bytes{};
};

struct Frame {
    u16 type = 0;
    Token token;
    std::vector<unsigned char> payload;
};

struct ProcIdentity {
    pid_t pid = -1;
    pid_t ppid = -1;
    pid_t sid = -1;
    u64 start = 0;
    pid_t pgid = -1;
    uid_t uid = static_cast<uid_t>(-1);
    gid_t gid = static_cast<gid_t>(-1);
    ino_t netns = 0;
    dev_t exe_dev = 0;
    ino_t exe_ino = 0;
    std::string exe;
    std::string cmdline;
    bool no_new_privs = false;
    bool capabilities_clear = false;
    size_t supplementary_groups = 0;
};

struct Report {
    u64 target_pid = 0;
    u64 wrapper_pid = 0;
    u64 start = 0;
    u64 pgid = 0;
    u64 uid = 0;
    u64 gid = 0;
    u64 netns = 0;
    u64 exe_dev = 0;
    u64 exe_ino = 0;
    u64 no_new_privs = 0;
    u64 capabilities_clear = 0;
    u64 groups_clear = 0;
    u64 groups_unchanged = 0;
    std::string exe;
    std::string argv;
    std::string mode;
};

struct Peer {
    pid_t pid = -1;
    uid_t uid = static_cast<uid_t>(-1);
    gid_t gid = static_cast<gid_t>(-1);
};

struct Child {
    pid_t pid = -1;
    pid_t target_pid = -1;
    int status = 0;
    bool reaped = false;
};

bool read_file(const std::string& path, std::string& out, size_t limit = 128 * 1024);
bool wait_fd(int fd, short events, std::chrono::steady_clock::time_point deadline);
bool write_exact(int fd, const unsigned char* data, size_t size, int timeout_ms);
bool read_exact(int fd, unsigned char* data, size_t size, int timeout_ms);
bool receive_frame_until(int fd, Frame& frame, std::chrono::steady_clock::time_point deadline);
std::vector<unsigned char> frame_bytes(const Frame& frame);
bool send_frame(int fd, const Frame& frame, int timeout_ms);
bool valid_frame_header(const unsigned char* header, const Token& expected);
bool receive_frame(int fd, Frame& frame, int timeout_ms);
bool token_equal(const Token& a, const Token& b);
bool read_proc(pid_t pid, ProcIdentity& result, bool require_capabilities_clear = true);
bool get_peer(int fd, Peer& peer);
int connect_control(const char* path);
bool child_security_setup(u64& groups_clear);
bool token_from_hex(const char* text, Token& token);
std::string make_expected_argv(const char* executable,
                               const char* path,
                               const char* token,
                               const char* mode,
                               const char* role = "--fixture-worker");
std::vector<unsigned char> encode_report(const Report& report);
bool decode_report(const std::vector<unsigned char>& payload, Report& report);
bool identity_matches_report(const Report& report,
                             const Peer& peer,
                             const ProcIdentity& proc,
                             const std::string& expected_exe,
                             const std::string& expected_argv,
                             const std::string& expected_mode,
                             const Token& token,
                             const Token& frame_token,
                             bool authority,
                             bool require_wrapper_equal,
                             bool require_groups_clear = false);
bool process_alive(pid_t pid);
bool same_process_identity(const ProcIdentity& a, const ProcIdentity& b);
bool reap_bounded(Child& child, int timeout_ms);
bool target_gone_or_reused(const ProcIdentity& before);
bool safe_cleanup(Child& child,
                  const Report& report,
                  const Peer& peer,
                  const ProcIdentity& before,
                  const Token& token,
                  const Token& frame_token,
                  bool authority);
bool safe_cleanup_unready(Child& child,
                          const ProcIdentity& expected,
                          const std::string& expected_argv,
                          bool authority);
bool safe_cleanup_orphan_target(pid_t target_pid, const ProcIdentity& expected, bool authority);
bool create_listener(const std::string& path, int& fd);
bool accept_bounded(int listener, int& fd);

}  // namespace rut::test::fixture_worker_protocol
