#pragma once

#include "rut/common/shard_limits.h"
#include "rut/runtime/arena.h"
#include "rut/runtime/jwt_rs256.h"
#include "rut/runtime/public_key.h"

namespace rut {
// Immutable, configuration-owned trust policy. Only explicitly approved keys
// are imported. Public key parsing never runs on the request path.
class Rs256Policy {
public:
    static constexpr u32 kMaxText = 8192;
    static constexpr u32 kMaxName = 1024;
    bool load(Str configuration);
    const Rs256KeySet& keys() const { return keys_; }
    Str issuer() const { return {issuer_, issuer_len_}; }
    Str audience() const { return {audience_, audience_len_}; }

private:
    Rs256KeySet keys_;
    char issuer_[kMaxName]{};
    char audience_[kMaxName]{};
    u32 issuer_len_ = 0;
    u32 audience_len_ = 0;
};

// One owner per configuration generation, retained until all RCU readers retire.
// All storage is allocated before publication. Each activation and verification
// touches only its shard's mutable row; no request-time initialization/fallback.
class Rs256Policies {
public:
    static constexpr u32 kMaxPolicies = 8;
    Rs256Policies() = default;
    Rs256Policies(const Rs256Policies&) = delete;
    Rs256Policies& operator=(const Rs256Policies&) = delete;
    ~Rs256Policies() { destroy(); }
    bool load(const Str* configurations, u32 count);
    bool activate(u32 shard);
    bool verify(u32 shard,
                Str configuration,
                json::Document& document,
                Str token,
                i64 now,
                char* payload,
                u32 capacity,
                u32& length);
    void destroy();

private:
    struct Row {
        Rs256VerifierSet verifiers[kMaxPolicies];
        bool attempted = false;
        bool ready = false;
    };
    MmapArena arena_;
    Rs256Policy* policies_ = nullptr;
    Row* rows_ = nullptr;
    Str configurations_[kMaxPolicies]{};
    u32 count_ = 0;
};
}  // namespace rut
