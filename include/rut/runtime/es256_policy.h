#pragma once

#include "rut/common/shard_limits.h"
#include "rut/runtime/arena.h"
#include "rut/runtime/ec_public_key.h"
#include "rut/runtime/jwt_es256.h"

namespace rut {

// Immutable configuration-owned ES256 trust profile. Only explicitly approved
// IDs are loaded, with exact issuer/audience and optional revocation snapshots.
// This profile accepts local JWKS only; remoteJwks is rejected, not ignored.
class Es256Policy {
public:
    static constexpr u32 kMaxText = 8192;
    static constexpr u32 kMaxName = 1024;
    static constexpr u32 kMaxRevokedJtis = 64;
    static constexpr u32 kMaxJtiBytes = 128;
    bool load(Str configuration);
    bool load_jwks(Str jwks, Str issuer, Str audience, const Str* approved_ids, u32 count);
    const Es256KeySet& keys() const { return key_set; }
    Str issuer() const { return {issuer_bytes, issuer_len}; }
    Str audience() const { return {audience_bytes, audience_len}; }
    bool permits(json::Document& document) const;

private:
    bool import_jwks(Str jwks, Str issuer, Str audience, const Str* approved_ids, u32 count);
    Es256KeySet key_set;
    char issuer_bytes[kMaxName]{};
    char audience_bytes[kMaxName]{};
    u32 issuer_len = 0;
    u32 audience_len = 0;
    char revoked_jtis[kMaxRevokedJtis][kMaxJtiBytes]{};
    u32 revoked_lengths[kMaxRevokedJtis]{};
    u32 revoked_count = 0;
    bool require_jti = false;
    i64 issued_after = 0;
};

class Es256Policies {
public:
    static constexpr u32 kMaxPolicies = 8;
    Es256Policies() = default;
    Es256Policies(const Es256Policies&) = delete;
    Es256Policies& operator=(const Es256Policies&) = delete;
    ~Es256Policies() { destroy(); }
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
        Es256VerifierSet verifiers[kMaxPolicies];
        bool attempted = false;
        bool ready = false;
    };
    MmapArena arena;
    Es256Policy* policies = nullptr;
    Row* rows = nullptr;
    Str configurations[kMaxPolicies]{};
    u32 count = 0;
};
}  // namespace rut
