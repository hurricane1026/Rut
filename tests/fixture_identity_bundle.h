#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include <sys/types.h>

namespace rut::test::fixture_identity_bundle {

using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

constexpr u32 kMagic = 0x31424449u;  // "IDB1"
constexpr u16 kVersion = 1;
constexpr size_t kRoleCount = 2;
constexpr size_t kFdsPerRole = 6;
constexpr size_t kBundleFdCount = kRoleCount * kFdsPerRole;
constexpr size_t kHeaderBytes = 16;
constexpr size_t kRoleManifestBytes = 14 * sizeof(u64);
constexpr size_t kPayloadBytes = kRoleCount * kRoleManifestBytes;
constexpr size_t kWireBytes = kHeaderBytes + kPayloadBytes;
constexpr int kTransportTimeoutMs = 1000;
static_assert(kRoleCount == 2 && kFdsPerRole == 6 && kBundleFdCount == 12);
static_assert(kRoleManifestBytes == 112 && kWireBytes == 240);

enum class Role : u16 { Launcher = 1, Root = 2 };

enum class FdSlot : size_t {
    Stat = 0,
    Status = 1,
    Cmdline = 2,
    Executable = 3,
    Netns = 4,
    Pidfd = 5,
};

struct RoleManifest {
    Role role = Role::Launcher;
    pid_t pid = -1;
    u64 start = 0;
    pid_t ppid = -1;
    pid_t pgid = -1;
    pid_t sid = -1;
    uid_t uid = static_cast<uid_t>(-1);
    gid_t gid = static_cast<gid_t>(-1);
    u64 netns = 0;
    u64 exe_dev = 0;
    u64 exe_ino = 0;
    u64 argv_length = 0;
    u64 argv_hash = 0;
};

struct RoleBundle {
    RoleManifest manifest;
    std::array<int, kFdsPerRole> fds{};

    RoleBundle();
    ~RoleBundle();
    RoleBundle(const RoleBundle&) = delete;
    RoleBundle& operator=(const RoleBundle&) = delete;
    RoleBundle(RoleBundle&& other) noexcept;
    RoleBundle& operator=(RoleBundle&& other) noexcept;
    void close();
};

struct IdentityBundle {
    std::array<RoleBundle, kRoleCount> roles;

    IdentityBundle() = default;
    IdentityBundle(const IdentityBundle&) = delete;
    IdentityBundle& operator=(const IdentityBundle&) = delete;
    IdentityBundle(IdentityBundle&&) noexcept = default;
    IdentityBundle& operator=(IdentityBundle&&) noexcept = default;
    void close();
};

class ReceivedBundle {
public:
    ReceivedBundle() = default;
    ~ReceivedBundle() = default;
    ReceivedBundle(const ReceivedBundle&) = delete;
    ReceivedBundle& operator=(const ReceivedBundle&) = delete;
    ReceivedBundle(ReceivedBundle&&) noexcept = default;
    ReceivedBundle& operator=(ReceivedBundle&&) noexcept = default;

    IdentityBundle& bundle() { return bundle_; }
    const IdentityBundle& bundle() const { return bundle_; }
    void reset() { bundle_.close(); }

private:
    IdentityBundle bundle_;
};

bool open_role(pid_t pid, Role role, RoleBundle& role_bundle, std::string& error);
bool adopt_role(Role role,
                std::array<int, kFdsPerRole>& inherited_fds,
                RoleBundle& role_bundle,
                std::string& error);
bool validate_bundle(const IdentityBundle& bundle, std::string& error);
std::vector<unsigned char> encode_bundle(const IdentityBundle& bundle);
bool send_bundle(int fd,
                 const IdentityBundle& bundle,
                 std::chrono::steady_clock::time_point deadline);
bool receive_bundle(int fd,
                    ReceivedBundle& bundle,
                    std::chrono::steady_clock::time_point deadline,
                    std::string& error);

}  // namespace rut::test::fixture_identity_bundle
