#pragma once

#include "fixture_direct_launch.h"
#include "fixture_identity_bundle.h"
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace rut::test::fixture_ancestry_bundle {

namespace identity = fixture_identity_bundle;
using u16 = std::uint16_t;
using u32 = std::uint32_t;

constexpr u32 kMagic = 0x31434e41u;  // "ANC1"
constexpr u16 kVersion = 1;
constexpr u16 kType = 1;
constexpr u16 kAnchorLast = 1;
constexpr size_t kHeaderBytes = 16;
constexpr size_t kMaxNodes = fixture_direct_launch::kMaxLaunchAncestry;
constexpr size_t kFdsPerNode = identity::kFdsPerRole;
constexpr size_t kMaxFdCount = kMaxNodes * kFdsPerNode;
constexpr int kTransportTimeoutMs = 1000;
static_assert(kHeaderBytes == 16 && kMaxNodes == 8 && kFdsPerNode == 6 && kMaxFdCount == 48);

// ANC1 is header-only: magic/u16 version/u16 type/u16 node-count/
// u16 fd-count/u16 anchor-last-flags/u16 reserved.  There is no manifest,
// PID, argv, or other self-reported payload.
struct AncestryBundle {
    std::vector<identity::RoleBundle> nodes;

    AncestryBundle() = default;
    AncestryBundle(const AncestryBundle&) = delete;
    AncestryBundle& operator=(const AncestryBundle&) = delete;
    AncestryBundle(AncestryBundle&&) noexcept = default;
    AncestryBundle& operator=(AncestryBundle&&) noexcept = default;
    ~AncestryBundle() = default;

    void close();
};

std::vector<unsigned char> encode_header(size_t node_count);
bool validate_bundle(const AncestryBundle& bundle, std::string& error);
bool send_bundle(int fd,
                 const AncestryBundle& bundle,
                 std::chrono::steady_clock::time_point deadline);
bool receive_bundle(int fd,
                    AncestryBundle& bundle,
                    std::chrono::steady_clock::time_point deadline,
                    std::string& error);
bool extract_evidence(const AncestryBundle& bundle,
                      std::vector<identity::ProcessIdentityEvidence>& evidence,
                      std::string& error);

}  // namespace rut::test::fixture_ancestry_bundle
