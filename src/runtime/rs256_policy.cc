#include "rut/runtime/rs256_policy.h"

#include "rut/common/shard_limits.h"
#include "rut/common/types.h"
#include "rut/runtime/crypto_c.h"
#include "rut/runtime/json.h"
#include "rut/runtime/jwt_rs256.h"
#include <new>

namespace rut {
bool Rs256Policy::load_jwks(
    Str jwks, Str issuer, Str audience, const Str* approved_ids, u32 count) {
    if (keys_.valid() || !issuer.ptr || issuer.len == 0 || issuer.len > kMaxName || !audience.ptr ||
        audience.len == 0 || audience.len > kMaxName)
        return false;
    if (!approved_ids || count == 0 || count > Rs256KeySet::kMaxKeys) return false;
    rut_crypto_span_v1 ids[Rs256KeySet::kMaxKeys]{};
    for (u32 i = 0; i < count; ++i)
        ids[i] = {reinterpret_cast<const uint8_t*>(approved_ids[i].ptr), approved_ids[i].len};
    if (!rut_crypto_rsa_key_set_load_v1(reinterpret_cast<rut_crypto_rsa_key_set_v1*>(&keys_),
                                        reinterpret_cast<const uint8_t*>(jwks.ptr),
                                        jwks.len,
                                        ids,
                                        count))
        return false;
    char issuer_copy[kMaxName];
    char audience_copy[kMaxName];
    __builtin_memcpy(issuer_copy, issuer.ptr, issuer.len);
    __builtin_memcpy(audience_copy, audience.ptr, audience.len);
    __builtin_memcpy(issuer_, issuer_copy, issuer.len);
    __builtin_memcpy(audience_, audience_copy, audience.len);
    issuer_len_ = issuer.len;
    audience_len_ = audience.len;
    return true;
}

bool Rs256Policy::load(Str configuration) {
    if (keys_.valid() || !configuration.ptr || configuration.len > kMaxText) return false;
    json::Document document;
    if (!document.parse(configuration) || document.nodes[0].kind != json::Kind::Object)
        return false;
    u32 jwks = json::kNone;
    u32 kids = json::kNone;
    u32 fields = 0;
    for (u32 n = document.nodes[0].child; n != json::kNone; n = document.nodes[n].next) {
        json::Writer key{document.scratch};
        if (!document.string(document.nodes[n].key, key)) return false;
        const Str kName{document.scratch, key.len};
        if (kName.eq(lit_str("jwks"))) {
            if (document.nodes[n].kind != json::Kind::Object) return false;
            jwks = n;
        } else if (kName.eq(lit_str("kids"))) {
            if (document.nodes[n].kind != json::Kind::Array) return false;
            kids = n;
        } else if (kName.eq(lit_str("issuer")) || kName.eq(lit_str("audience"))) {
            const bool kIssuer = kName.eq(lit_str("issuer"));
            json::Writer value{kIssuer ? issuer_ : audience_, kMaxName};
            if (!document.string(n, value) || !value.ok || value.len == 0) return false;
            (kIssuer ? issuer_len_ : audience_len_) = value.len;
        } else {
            return false;
        }
        ++fields;
    }
    if (fields != 4 || jwks == json::kNone || kids == json::kNone || !issuer_len_ || !audience_len_)
        return false;
    char ids[Rs256KeySet::kMaxKeys][Rs256KeySet::kMaxKidBytes];
    Str approved[Rs256KeySet::kMaxKeys];
    u32 count = 0;
    for (u32 n = document.nodes[kids].child; n != json::kNone; n = document.nodes[n].next) {
        if (count == Rs256KeySet::kMaxKeys) return false;
        json::Writer id{ids[count], Rs256KeySet::kMaxKidBytes};
        if (!document.string(n, id) || !id.ok || !id.len) return false;
        approved[count] = {ids[count], id.len};
        ++count;
    }
    return load_jwks(document.raw(jwks), issuer(), audience(), approved, count);
}

bool Rs256Policies::load(const Str* configurations, u32 count) {
    if (policies_ || rows_ || count > kMaxPolicies || (count && !configurations)) return false;
    if (!count) return true;
    if (!arena_.init(4096)) return false;
    policies_ = static_cast<Rs256Policy*>(arena_.alloc(sizeof(Rs256Policy) * count));
    if (!policies_) {
        destroy();
        return false;
    }
    for (u32 i = 0; i < count; ++i) {
        ::new (&policies_[i]) Rs256Policy();
        ++count_;
        if (!policies_[i].load(configurations[i])) {
            destroy();
            return false;
        }
        auto* bytes = static_cast<char*>(arena_.alloc(configurations[i].len));
        if (!bytes) {
            destroy();
            return false;
        }
        __builtin_memcpy(bytes, configurations[i].ptr, configurations[i].len);
        configurations_[i] = {bytes, configurations[i].len};
    }
    rows_ = static_cast<Row*>(arena_.alloc(sizeof(Row) * kMaxShards));
    if (!rows_) {
        destroy();
        return false;
    }
    for (u32 i = 0; i < kMaxShards; ++i) ::new (&rows_[i]) Row();
    return true;
}

bool Rs256Policies::activate(u32 shard) {
    if (!count_) return true;
    if (!rows_ || shard >= kMaxShards) return false;
    auto& row = rows_[shard];
    if (row.attempted) return row.ready;
    row.attempted = true;
    for (u32 i = 0; i < count_; ++i) {
        if (!row.verifiers[i].init(policies_[i].keys())) {
            for (u32 j = 0; j <= i; ++j) row.verifiers[j].reset();
            return false;
        }
    }
    row.ready = true;
    return true;
}

bool Rs256Policies::verify(u32 shard,
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
    if (!rows_ || shard >= kMaxShards || !rows_[shard].ready) return false;
    for (u32 i = 0; i < count_; ++i) {
        if (!configurations_[i].eq(configuration)) continue;
        Str kid{};
        return jwt_rs256_validate_set(rows_[shard].verifiers[i],
                                      document,
                                      token,
                                      policies_[i].issuer(),
                                      policies_[i].audience(),
                                      now,
                                      payload,
                                      capacity,
                                      length,
                                      kid);
    }
    return false;
}

void Rs256Policies::destroy() {
    if (rows_) {
        for (u32 i = 0; i < kMaxShards; ++i) rows_[i].~Row();
    }
    for (u32 i = 0; i < count_; ++i) policies_[i].~Rs256Policy();
    rows_ = nullptr;
    policies_ = nullptr;
    count_ = 0;
    arena_.destroy();
}
}  // namespace rut
