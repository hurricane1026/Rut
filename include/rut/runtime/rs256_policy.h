#pragma once

#include "rut/common/shard_limits.h"
#include "rut/runtime/arena.h"
#include "rut/runtime/jwt_rs256.h"
#include "rut/runtime/public_key.h"
#include "rut/runtime/remote_jwks.h"

namespace rut {
// Immutable, configuration-owned trust policy. Only explicitly approved keys
// are imported. Public key parsing never runs on the request path.
class Rs256Policy {
public:
    static constexpr u32 kMaxText = 8192;
    static constexpr u32 kMaxName = 1024;
    static constexpr u32 kMaxRevokedJtis = 64;
    static constexpr u32 kMaxJtiBytes = 128;
    bool load(Str configuration);
    // Configuration-time import of a separately obtained JWKS. Issuer,
    // audience and approved key IDs must come from trusted configuration.
    // Failed imports leave the policy unactivated; successful imports own all
    // key material and metadata independently of the input buffers.
    bool load_jwks(Str jwks, Str issuer, Str audience, const Str* approved_ids, u32 count);
    const Rs256KeySet& keys() const { return keys_; }
    Str issuer() const { return {issuer_, issuer_len_}; }
    Str audience() const { return {audience_, audience_len_}; }
    Str required_type() const { return {type_bytes, type_length}; }
    // Apply only to signature/claims-verified documents. Immutable snapshot:
    // changes take effect with configuration adoption, retaining old RCU readers.
    bool permits(json::Document& document) const;
    using Remote = RemoteJwks;
    const Remote& remote() const { return remote_; }
    // Accept only the intersection with configuration-approved IDs. Empty is a
    // valid authoritative removal of all trusted keys; malformed sets are not.
    enum class Refresh : u8 { Invalid, Empty, Ready };
    Refresh prepare_refresh(Str jwks, Rs256KeySet& output) const;

private:
    bool import_jwks(Str jwks, Str issuer, Str audience, const Str* approved_ids, u32 count);
    Rs256KeySet keys_;
    char issuer_[kMaxName]{};
    char audience_[kMaxName]{};
    u32 issuer_len_ = 0;
    u32 audience_len_ = 0;
    char revoked_jtis_[kMaxRevokedJtis][kMaxJtiBytes]{};
    u32 revoked_lengths_[kMaxRevokedJtis]{};
    u32 revoked_count_ = 0;
    bool require_jti_ = false;
    i64 issued_after_ = 0;
    char type_bytes[kMaxJwtTypeBytes]{};
    u32 type_length = 0;
    Remote remote_{};
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
                u32& length,
                u64 monotonic_ms = ~u64{0});
    // Shard maintenance only: never called from the verifier. No blocking DNS,
    // readiness waits, lazy initialization or token-triggered refresh.
    void maintain(u32 shard, u64 monotonic_ms = ~u64{0});
    bool fetch_busy(u32 shard) const;
    void cancel(u32 shard);
    void destroy();

private:
    struct RemoteRow {
        HttpsFetch fetch;
        Rs256VerifierSet alternate;
        u64 last_success = 0;
        u64 next_attempt = 0;
        bool use_alternate = false;
        bool empty = false;
    };
    struct Row {
        Rs256VerifierSet verifiers[kMaxPolicies];
        RemoteRow* remote[kMaxPolicies]{};
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
