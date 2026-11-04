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
    if (!import_jwks(jwks, issuer, audience, approved_ids, count)) return false;
    revoked_count_ = 0;
    require_jti_ = false;
    issued_after_ = 0;
    type_length = 0;
    remote_ = {};
    return true;
}

bool Rs256Policy::import_jwks(
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
    u32 required = 0;
    revoked_count_ = 0;
    require_jti_ = false;
    issued_after_ = 0;
    type_length = 0;
    remote_ = {};
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
            json::Writer value{kIssuer ? issuer_ : audience_, kMaxName};
            if (!document.string(n, value) || !value.ok || value.len == 0) return false;
            (kIssuer ? issuer_len_ : audience_len_) = value.len;
            required |= kIssuer ? 4 : 8;
        } else if (kName.eq(lit_str("requiredType"))) {
            json::Writer value{type_bytes, sizeof(type_bytes)};
            if (!document.string(n, value) || !value.ok || !value.len) return false;
            for (u32 i = 0; i < value.len; ++i)
                if (type_bytes[i] < 0x21 || type_bytes[i] > 0x7e) return false;
            type_length = value.len;
        } else if (kName.eq(lit_str("revokedJtis"))) {
            if (document.nodes[n].kind != json::Kind::Array) return false;
            require_jti_ = true;
            for (u32 entry = document.nodes[n].child; entry != json::kNone;
                 entry = document.nodes[entry].next) {
                if (revoked_count_ == kMaxRevokedJtis) return false;
                json::Writer id{revoked_jtis_[revoked_count_], kMaxJtiBytes};
                if (!document.string(entry, id) || !id.ok || id.len == 0) return false;
                const Str kValue{revoked_jtis_[revoked_count_], id.len};
                for (u32 i = 0; i < revoked_count_; ++i)
                    if (kValue.eq({revoked_jtis_[i], revoked_lengths_[i]})) return false;
                revoked_lengths_[revoked_count_++] = id.len;
            }
        } else if (kName.eq(lit_str("remoteJwks"))) {
            if (!remote_.load(document, n)) return false;
        } else if (kName.eq(lit_str("issuedAfter"))) {
            if (document.nodes[n].kind != json::Kind::Number ||
                !json::integer(document.raw(n), issued_after_) || issued_after_ <= 0)
                return false;
        } else {
            return false;
        }
    }
    if (required != 15 || jwks == json::kNone || kids == json::kNone) return false;
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
    return import_jwks(document.raw(jwks), issuer(), audience(), approved, count);
}

bool Rs256Policy::permits(json::Document& document) const {
    if (!keys_.valid() || !document.valid || document.nodes[0].kind != json::Kind::Object)
        return false;
    if (!require_jti_ && !issued_after_) return true;
    bool has_jti = false;
    bool has_iat = false;
    for (u32 n = document.nodes[0].child; n != json::kNone; n = document.nodes[n].next) {
        json::Writer name{document.scratch};
        if (!document.string(document.nodes[n].key, name)) return false;
        const Str kKey{document.scratch, name.len};
        if (require_jti_ && kKey.eq(lit_str("jti"))) {
            json::Writer id{document.other, kMaxJtiBytes};
            if (!document.string(n, id) || !id.ok || !id.len) return false;
            const Str kValue{document.other, id.len};
            for (u32 i = 0; i < revoked_count_; ++i)
                if (kValue.eq({revoked_jtis_[i], revoked_lengths_[i]})) return false;
            has_jti = true;
        } else if (issued_after_ && kKey.eq(lit_str("iat"))) {
            i64 issued = 0;
            if (document.nodes[n].kind != json::Kind::Number ||
                !json::integer(document.raw(n), issued) || issued <= issued_after_)
                return false;
            has_iat = true;
        }
    }
    return (!require_jti_ || has_jti) && (!issued_after_ || has_iat);
}

Rs256Policy::Refresh Rs256Policy::prepare_refresh(Str jwks, Rs256KeySet& output) const {
    if (!keys_.valid() || output.valid()) return Refresh::Invalid;
    json::Document document;
    if (!document.parse(jwks) || document.nodes[0].kind != json::Kind::Object)
        return Refresh::Invalid;
    u32 entries = json::kNone;
    for (u32 n = document.nodes[0].child; n != json::kNone; n = document.nodes[n].next) {
        json::Writer key{document.scratch};
        if (!document.string(document.nodes[n].key, key)) return Refresh::Invalid;
        if (Str{document.scratch, key.len}.eq(lit_str("keys"))) entries = n;
    }
    if (entries == json::kNone || document.nodes[entries].kind != json::Kind::Array)
        return Refresh::Invalid;
    char ids[Rs256KeySet::kMaxKeys][Rs256KeySet::kMaxKidBytes];
    u32 lengths[Rs256KeySet::kMaxKeys];
    Str approved[Rs256KeySet::kMaxKeys];
    u32 count = 0, selected = 0;
    for (u32 n = document.nodes[entries].child; n != json::kNone; n = document.nodes[n].next) {
        if (count == Rs256KeySet::kMaxKeys || document.nodes[n].kind != json::Kind::Object)
            return Refresh::Invalid;
        u32 kid = json::kNone;
        for (u32 member = document.nodes[n].child; member != json::kNone;
             member = document.nodes[member].next) {
            json::Writer name{document.scratch};
            if (!document.string(document.nodes[member].key, name)) return Refresh::Invalid;
            if (Str{document.scratch, name.len}.eq(lit_str("kid"))) kid = member;
        }
        if (kid == json::kNone) return Refresh::Invalid;
        json::Writer id{ids[count], sizeof(ids[count])};
        if (!document.string(kid, id) || !id.ok || !id.len) return Refresh::Invalid;
        const Str kValue{ids[count], id.len};
        for (u32 i = 0; i < count; ++i)
            if (kValue.eq({ids[i], lengths[i]})) return Refresh::Invalid;
        lengths[count++] = id.len;
        for (u32 i = 0; i < keys_.size(); ++i) {
            if (kValue.eq(keys_.kid_at(i))) approved[selected++] = keys_.kid_at(i);
        }
    }
    if (!selected) return Refresh::Empty;
    return output.load(jwks, approved, selected) ? Refresh::Ready : Refresh::Invalid;
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
    for (u32 shard = 0; shard < kMaxShards; ++shard) {
        for (u32 i = 0; i < count_; ++i) {
            if (!policies_[i].remote().enabled()) continue;
            void* storage = arena_.alloc(sizeof(RemoteRow));
            if (!storage) {
                destroy();
                return false;
            }
            rows_[shard].remote[i] = ::new (storage) RemoteRow();
        }
    }
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
    for (u32 i = 0; i < count_; ++i) {
        if (row.remote[i] && !row.remote[i]->fetch.init(policies_[i].remote().endpoint)) {
            for (u32 j = 0; j < count_; ++j) row.verifiers[j].reset();
            cancel(shard);
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
                           u32& length,
                           u64 monotonic_ms) {
    length = 0;
    document.valid = false;
    document.count = 0;
    document.source = {};
    if (!rows_ || shard >= kMaxShards || !rows_[shard].ready) return false;
    for (u32 i = 0; i < count_; ++i) {
        if (!configurations_[i].eq(configuration)) continue;
        auto& row = rows_[shard];
        Rs256VerifierSet* verifiers = &row.verifiers[i];
        if (auto* remote = row.remote[i]) {
            if (monotonic_ms == ~u64{0}) monotonic_ms = jwt_monotonic_ms();
            if (!monotonic_ms || !remote->last_success || remote->empty ||
                monotonic_ms < remote->last_success ||
                monotonic_ms - remote->last_success >=
                    static_cast<u64>(policies_[i].remote().max_age_seconds) * 1000)
                return false;
            if (remote->use_alternate) verifiers = &remote->alternate;
        }
        Str kid{};
        if (jwt_rs256_validate_set(*verifiers,
                                   document,
                                   token,
                                   policies_[i].issuer(),
                                   policies_[i].audience(),
                                   now,
                                   payload,
                                   capacity,
                                   length,
                                   kid,
                                   policies_[i].required_type()) &&
            policies_[i].permits(document))
            return true;
        length = 0;
        document.valid = false;
        document.count = 0;
        document.source = {};
        return false;
    }
    return false;
}

void Rs256Policies::maintain(u32 shard, u64 monotonic_ms) {
    if (!rows_ || shard >= kMaxShards || !rows_[shard].ready) return;
    auto& row = rows_[shard];
    for (u32 i = 0; i < count_; ++i) {
        auto* remote = row.remote[i];
        if (!remote) continue;
        if (monotonic_ms == ~u64{0}) monotonic_ms = jwt_monotonic_ms();
        const auto& policy = policies_[i].remote();
        if (!monotonic_ms || (remote->last_success && monotonic_ms < remote->last_success)) {
            remote->fetch.cancel();
            remote->last_success = 0;
            remote->next_attempt = 0;
            continue;
        }
        if (remote->fetch.state() != HttpsFetch::State::Busy) {
            if (monotonic_ms < remote->next_attempt) continue;
            // Attempt start schedules the next retry too; setup failures cannot
            // turn every batch into a connection storm.
            remote->next_attempt = monotonic_ms + static_cast<u64>(policy.refresh_seconds) * 1000;
            (void)remote->fetch.start(monotonic_ms, policy.timeout_seconds * 1000);
        }
        remote->fetch.advance(monotonic_ms);
        if (remote->fetch.state() != HttpsFetch::State::Done) continue;
        Rs256KeySet keys;
        const auto kPrepared = policies_[i].prepare_refresh(remote->fetch.body(), keys);
        if (kPrepared != Rs256Policy::Refresh::Invalid) {
            auto& candidate = remote->use_alternate ? row.verifiers[i] : remote->alternate;
            candidate.reset();
            if (kPrepared == Rs256Policy::Refresh::Empty || candidate.init(keys)) {
                // This maintenance callback runs between handler batches on the
                // same shard. Verification retains no key/verifier views.
                auto& previous = remote->use_alternate ? remote->alternate : row.verifiers[i];
                previous.reset();
                remote->use_alternate = !remote->use_alternate;
                remote->empty = kPrepared == Rs256Policy::Refresh::Empty;
                remote->last_success = monotonic_ms;
                remote->next_attempt =
                    monotonic_ms + static_cast<u64>(policy.refresh_seconds) * 1000;
            }
        }
        // Release the borrowed body only after key import/activation completes.
        remote->fetch.cancel();
    }
}

void Rs256Policies::cancel(u32 shard) {
    if (!rows_ || shard >= kMaxShards) return;
    for (u32 i = 0; i < count_; ++i)
        if (rows_[shard].remote[i]) rows_[shard].remote[i]->fetch.cancel();
}

bool Rs256Policies::fetch_busy(u32 shard) const {
    if (!rows_ || shard >= kMaxShards || !rows_[shard].ready) return false;
    const auto& row = rows_[shard];
    for (u32 i = 0; i < count_; ++i)
        if (row.remote[i] && row.remote[i]->fetch.state() == HttpsFetch::State::Busy) return true;
    return false;
}

void Rs256Policies::destroy() {
    if (rows_) {
        for (u32 i = 0; i < kMaxShards; ++i) {
            for (u32 j = 0; j < count_; ++j)
                if (rows_[i].remote[j]) rows_[i].remote[j]->~RemoteRow();
            rows_[i].~Row();
        }
    }
    for (u32 i = 0; i < count_; ++i) policies_[i].~Rs256Policy();
    rows_ = nullptr;
    policies_ = nullptr;
    count_ = 0;
    arena_.destroy();
}
}  // namespace rut
