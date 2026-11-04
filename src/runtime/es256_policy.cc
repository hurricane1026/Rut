#include "rut/runtime/es256_policy.h"

#include "rut/common/shard_limits.h"
#include "rut/common/types.h"
#include "rut/runtime/json.h"
#include "rut/runtime/jwt_es256.h"
#include <new>

namespace rut {
bool Es256Policy::load_jwks(
    Str jwks, Str issuer, Str audience, const Str* approved_ids, u32 count) {
    if (!import_jwks(jwks, issuer, audience, approved_ids, count)) return false;
    revoked_count = 0;
    require_jti = false;
    issued_after = 0;
    return true;
}

bool Es256Policy::import_jwks(
    Str jwks, Str issuer, Str audience, const Str* approved_ids, u32 count) {
    if (key_set.valid() || !issuer.ptr || issuer.len == 0 || issuer.len > kMaxName ||
        !audience.ptr || audience.len == 0 || audience.len > kMaxName)
        return false;
    if (!approved_ids || count == 0 || count > Es256KeySet::kMaxKeys) return false;
    if (!key_set.load(jwks, approved_ids, count)) return false;
    char issuer_copy[kMaxName];
    char audience_copy[kMaxName];
    __builtin_memcpy(issuer_copy, issuer.ptr, issuer.len);
    __builtin_memcpy(audience_copy, audience.ptr, audience.len);
    __builtin_memcpy(issuer_bytes, issuer_copy, issuer.len);
    __builtin_memcpy(audience_bytes, audience_copy, audience.len);
    issuer_len = issuer.len;
    audience_len = audience.len;
    return true;
}

bool Es256Policy::load(Str configuration) {
    if (key_set.valid() || !configuration.ptr || configuration.len > kMaxText) return false;
    json::Document document;
    if (!document.parse(configuration) || document.nodes[0].kind != json::Kind::Object)
        return false;
    u32 jwks = json::kNone;
    u32 kids = json::kNone;
    u32 required = 0;
    revoked_count = 0;
    require_jti = false;
    issued_after = 0;
    for (u32 n = document.nodes[0].child; n != json::kNone; n = document.nodes[n].next) {
        json::Writer key{document.scratch};
        if (!document.string(document.nodes[n].key, key)) return false;
        const Str kName{document.scratch, key.len};
        if (kName.eq(lit_str("jwks"))) {
            if (document.nodes[n].kind != json::Kind::Object) return false;
            jwks = n;
            required |= 1;
        } else if (kName.eq(lit_str("kids"))) {
            if (document.nodes[n].kind != json::Kind::Array) return false;
            kids = n;
            required |= 2;
        } else if (kName.eq(lit_str("issuer")) || kName.eq(lit_str("audience"))) {
            const bool kIssuer = kName.eq(lit_str("issuer"));
            json::Writer value{kIssuer ? issuer_bytes : audience_bytes, kMaxName};
            if (!document.string(n, value) || !value.ok || value.len == 0) return false;
            (kIssuer ? issuer_len : audience_len) = value.len;
            required |= kIssuer ? 4 : 8;
        } else if (kName.eq(lit_str("revokedJtis"))) {
            if (document.nodes[n].kind != json::Kind::Array) return false;
            require_jti = true;
            for (u32 entry = document.nodes[n].child; entry != json::kNone;
                 entry = document.nodes[entry].next) {
                if (revoked_count == kMaxRevokedJtis) return false;
                json::Writer id{revoked_jtis[revoked_count], kMaxJtiBytes};
                if (!document.string(entry, id) || !id.ok || id.len == 0) return false;
                const Str kValue{revoked_jtis[revoked_count], id.len};
                for (u32 i = 0; i < revoked_count; ++i)
                    if (kValue.eq({revoked_jtis[i], revoked_lengths[i]})) return false;
                revoked_lengths[revoked_count++] = id.len;
            }
        } else if (kName.eq(lit_str("issuedAfter"))) {
            if (document.nodes[n].kind != json::Kind::Number ||
                !json::integer(document.raw(n), issued_after) || issued_after <= 0)
                return false;
        } else {
            return false;
        }
    }
    if (required != 15 || jwks == json::kNone || kids == json::kNone) return false;
    char ids[Es256KeySet::kMaxKeys][Es256KeySet::kMaxKidBytes];
    Str approved[Es256KeySet::kMaxKeys];
    u32 count = 0;
    for (u32 n = document.nodes[kids].child; n != json::kNone; n = document.nodes[n].next) {
        if (count == Es256KeySet::kMaxKeys) return false;
        json::Writer id{ids[count], Es256KeySet::kMaxKidBytes};
        if (!document.string(n, id) || !id.ok || !id.len) return false;
        approved[count] = {ids[count], id.len};
        ++count;
    }
    return import_jwks(document.raw(jwks), issuer(), audience(), approved, count);
}

bool Es256Policy::permits(json::Document& document) const {
    if (!key_set.valid() || !document.valid || document.nodes[0].kind != json::Kind::Object)
        return false;
    if (!require_jti && !issued_after) return true;
    bool has_jti = false;
    bool has_iat = false;
    for (u32 n = document.nodes[0].child; n != json::kNone; n = document.nodes[n].next) {
        json::Writer name{document.scratch};
        if (!document.string(document.nodes[n].key, name)) return false;
        const Str kKey{document.scratch, name.len};
        if (require_jti && kKey.eq(lit_str("jti"))) {
            json::Writer id{document.other, kMaxJtiBytes};
            if (!document.string(n, id) || !id.ok || !id.len) return false;
            const Str kValue{document.other, id.len};
            for (u32 i = 0; i < revoked_count; ++i)
                if (kValue.eq({revoked_jtis[i], revoked_lengths[i]})) return false;
            has_jti = true;
        } else if (issued_after && kKey.eq(lit_str("iat"))) {
            i64 issued = 0;
            if (document.nodes[n].kind != json::Kind::Number ||
                !json::integer(document.raw(n), issued) || issued <= issued_after)
                return false;
            has_iat = true;
        }
    }
    return (!require_jti || has_jti) && (!issued_after || has_iat);
}

bool Es256Policies::load(const Str* configuration_values, u32 configuration_count) {
    if (policies || rows || configuration_count > kMaxPolicies ||
        (configuration_count && !configuration_values))
        return false;
    if (!configuration_count) return true;
    if (!arena.init(4096)) return false;
    policies = static_cast<Es256Policy*>(arena.alloc(sizeof(Es256Policy) * configuration_count));
    if (!policies) {
        destroy();
        return false;
    }
    for (u32 i = 0; i < configuration_count; ++i) {
        ::new (&policies[i]) Es256Policy();
        ++count;
        if (!policies[i].load(configuration_values[i])) {
            destroy();
            return false;
        }
        auto* bytes = static_cast<char*>(arena.alloc(configuration_values[i].len));
        if (!bytes) {
            destroy();
            return false;
        }
        __builtin_memcpy(bytes, configuration_values[i].ptr, configuration_values[i].len);
        configurations[i] = {bytes, configuration_values[i].len};
    }
    rows = static_cast<Row*>(arena.alloc(sizeof(Row) * kMaxShards));
    if (!rows) {
        destroy();
        return false;
    }
    for (u32 i = 0; i < kMaxShards; ++i) ::new (&rows[i]) Row();
    return true;
}

bool Es256Policies::activate(u32 shard) {
    if (!count) return true;
    if (!rows || shard >= kMaxShards) return false;
    auto& row = rows[shard];
    if (row.attempted) return row.ready;
    row.attempted = true;
    for (u32 i = 0; i < count; ++i) {
        if (!row.verifiers[i].init(policies[i].keys())) {
            for (u32 j = 0; j <= i; ++j) row.verifiers[j].reset();
            return false;
        }
    }
    row.ready = true;
    return true;
}

bool Es256Policies::verify(u32 shard,
                           Str configuration,
                           json::Document& document,
                           Str token,
                           i64 now,
                           char* payload,
                           u32 capacity,
                           u32& length) {
    length = 0;
    document.valid = false;
    document.count = 0;
    document.source = {};
    if (!rows || shard >= kMaxShards || !rows[shard].ready) return false;
    for (u32 i = 0; i < count; ++i) {
        if (!configurations[i].eq(configuration)) continue;
        auto& row = rows[shard];
        Es256VerifierSet* verifiers = &row.verifiers[i];
        Str kid{};
        if (jwt_es256_validate_set(*verifiers,
                                   document,
                                   token,
                                   policies[i].issuer(),
                                   policies[i].audience(),
                                   now,
                                   payload,
                                   capacity,
                                   length,
                                   kid) &&
            policies[i].permits(document))
            return true;
        length = 0;
        document.valid = false;
        document.count = 0;
        document.source = {};
        return false;
    }
    return false;
}

void Es256Policies::destroy() {
    if (rows)
        for (u32 i = 0; i < kMaxShards; ++i) rows[i].~Row();
    for (u32 i = 0; i < count; ++i) policies[i].~Es256Policy();
    rows = nullptr;
    policies = nullptr;
    count = 0;
    arena.destroy();
}
}  // namespace rut
