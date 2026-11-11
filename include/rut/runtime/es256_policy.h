#pragma once

#include "rut/common/shard_limits.h"
#include "rut/runtime/arena.h"
#include "rut/runtime/ec_public_key.h"
#include "rut/runtime/jwt_es256.h"
#include "rut/runtime/remote_jwks.h"

namespace rut {

// Immutable configuration-owned ES256 trust profile. Only explicitly approved
// IDs are loaded, with exact issuer/audience and optional revocation snapshots.
// Remote refresh imports only the configured approved IDs, outside requests.
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
    Str required_type() const { return {type_bytes, type_length}; }
    bool permits(json::Document& document) const;
    using Remote = RemoteJwks;
    const Remote& remote() const { return remote_configuration; }
    enum class Refresh : u8 { Invalid, Empty, Ready };
    Refresh prepare_refresh(Str jwks, Es256KeySet& output) const;

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
    char type_bytes[kMaxEs256TypeBytes]{};
    u32 type_length = 0;
    Remote remote_configuration{};
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
                u32& length,
                u64 monotonic_ms = ~u64{0});
    void maintain(u32 shard, u64 monotonic_ms = ~u64{0});
    bool fetch_busy(u32 shard) const;
    void cancel(u32 shard);
    void destroy();

private:
    struct RemoteRow {
        JwksFetch fetch;
        Es256VerifierSet alternate;
        u64 last_success = 0;
        u64 next_attempt = 0;
        bool use_alternate = false;
        bool empty = false;
    };
    struct Row {
        Es256VerifierSet verifiers[kMaxPolicies];
        RemoteRow* remote[kMaxPolicies]{};
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
