#include "rut/runtime/ec_public_key.h"

#include "crypto_ec_math_internal.h"
#include "crypto_rsa_math_internal.h"
#include "rut/common/types.h"
#include "rut/runtime/json.h"

namespace rut {
namespace {
struct ErrorScope {
    u32 marked = rut_crypto_error_scope_begin_internal();
    ~ErrorScope() { rut_crypto_error_scope_end_internal(marked); }
};

bool jwk_string(json::Document& document, u32 node, Str expected) {
    if (document.nodes[node].kind != json::Kind::String) return false;
    json::Writer writer{document.other};
    return document.string(node, writer) && Str{document.other, writer.len}.eq(expected);
}

// A P-256 coordinate is exactly 32 octets, including leading zero bytes;
// RFC 7518 6.2.1.2/3 uses base64url, not RSA's minimal Base64urlUInt profile.
bool coordinate(Str input, u8 (&output)[32]) {
    if (!input.ptr || input.len != 43) return false;
    u32 accumulator = 0, bits = 0, length = 0;
    for (u32 i = 0; i < input.len; ++i) {
        const char kC = input.ptr[i];
        u32 value;
        if (kC >= 'A' && kC <= 'Z')
            value = static_cast<u32>(kC - 'A');
        else if (kC >= 'a' && kC <= 'z')
            value = static_cast<u32>(kC - 'a' + 26);
        else if (kC >= '0' && kC <= '9')
            value = static_cast<u32>(kC - '0' + 52);
        else if (kC == '-')
            value = 62;
        else if (kC == '_')
            value = 63;
        else
            return false;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (length == sizeof(output)) return false;
            output[length++] = static_cast<u8>((accumulator >> bits) & 255);
        }
    }
    return length == sizeof(output) && (accumulator & 3u) == 0;
}
}  // namespace

EcP256PublicKey::~EcP256PublicKey() {
    reset();
}

void EcP256PublicKey::reset() {
    rut_crypto_rsa_key_free_internal(key);
    key = nullptr;
}

bool EcP256PublicKey::load(Str der) {
    if (key || !der.ptr || !der.len || der.len > kMaxDerBytes) return false;
    const ErrorScope kErrors;
    key = rut_crypto_ec_load_der_internal(reinterpret_cast<const u8*>(der.ptr), der.len);
    return key != nullptr;
}

bool EcP256PublicKey::load_es256_jwk(Str jwk) {
    if (key || !jwk.ptr || !jwk.len || jwk.len > kMaxDerBytes) return false;
    const ErrorScope kErrors;
    json::Document document;
    if (!document.parse(jwk) || document.nodes[0].kind != json::Kind::Object) return false;
    u32 required = 0;
    u8 x[32], y[32];
    for (u32 node = document.nodes[0].child; node != json::kNone;
         node = document.nodes[node].next) {
        json::Writer writer{document.scratch};
        if (!document.string(document.nodes[node].key, writer)) return false;
        const Str kName{document.scratch, writer.len};
        if (kName.eq(lit_str("kty"))) {
            if (!jwk_string(document, node, lit_str("EC"))) return false;
            required |= 1;
        } else if (kName.eq(lit_str("alg"))) {
            if (!jwk_string(document, node, lit_str("ES256"))) return false;
            required |= 2;
        } else if (kName.eq(lit_str("crv"))) {
            if (!jwk_string(document, node, lit_str("P-256"))) return false;
            required |= 4;
        } else if (kName.eq(lit_str("x")) || kName.eq(lit_str("y"))) {
            const bool kIsX = kName.eq(lit_str("x"));
            json::Writer value{document.other};
            if (!document.string(node, value) ||
                !coordinate({document.other, value.len}, kIsX ? x : y))
                return false;
            required |= kIsX ? 8 : 16;
        } else if (kName.eq(lit_str("use"))) {
            if (!jwk_string(document, node, lit_str("sig"))) return false;
        } else if (kName.eq(lit_str("key_ops"))) {
            const u32 kChild = document.nodes[node].child;
            if (document.nodes[node].kind != json::Kind::Array || kChild == json::kNone ||
                document.nodes[kChild].next != json::kNone ||
                !jwk_string(document, kChild, lit_str("verify")))
                return false;
        } else if (kName.eq(lit_str("d")) || kName.eq(lit_str("p")) || kName.eq(lit_str("q")) ||
                   kName.eq(lit_str("dp")) || kName.eq(lit_str("dq")) || kName.eq(lit_str("qi")) ||
                   kName.eq(lit_str("oth")))
            return false;
    }
    if (required != 31) return false;
    key = rut_crypto_ec_from_coordinates_internal(x, y);
    return key != nullptr;
}

bool EcP256PublicKey::load_es256_jwks(Str jwks, Str configured_kid) {
    if (key || !jwks.ptr || !jwks.len || jwks.len > kMaxDerBytes || !configured_kid.ptr ||
        !configured_kid.len || configured_kid.len > Es256KeySet::kMaxKidBytes)
        return false;
    json::Document document;
    if (!document.parse(jwks) || document.nodes[0].kind != json::Kind::Object) return false;
    u32 keys = json::kNone;
    for (u32 node = document.nodes[0].child; node != json::kNone;
         node = document.nodes[node].next) {
        json::Writer name{document.scratch};
        if (!document.string(document.nodes[node].key, name)) return false;
        if (Str{document.scratch, name.len}.eq(lit_str("keys"))) keys = node;
    }
    if (keys == json::kNone || document.nodes[keys].kind != json::Kind::Array) return false;
    char ids[Es256KeySet::kMaxKeys][Es256KeySet::kMaxKidBytes];
    u32 lengths[Es256KeySet::kMaxKeys];
    u32 count = 0, selected = json::kNone;
    for (u32 node = document.nodes[keys].child; node != json::kNone;
         node = document.nodes[node].next) {
        if (count == Es256KeySet::kMaxKeys || document.nodes[node].kind != json::Kind::Object)
            return false;
        u32 kid = json::kNone;
        for (u32 member = document.nodes[node].child; member != json::kNone;
             member = document.nodes[member].next) {
            json::Writer name{document.scratch};
            if (!document.string(document.nodes[member].key, name)) return false;
            if (Str{document.scratch, name.len}.eq(lit_str("kid"))) kid = member;
        }
        if (kid == json::kNone) return false;
        json::Writer id{ids[count], sizeof(ids[count])};
        if (!document.string(kid, id) || !id.ok || !id.len) return false;
        const Str kValue{ids[count], id.len};
        for (u32 i = 0; i < count; ++i)
            if (kValue.eq({ids[i], lengths[i]})) return false;
        lengths[count++] = id.len;
        if (kValue.eq(configured_kid)) selected = node;
    }
    if (selected == json::kNone) return false;
    json::Writer output{document.other};
    return document.write(selected, output) && load_es256_jwk({document.other, output.len});
}

EcP256Sha256Verifier::~EcP256Sha256Verifier() {
    reset();
}

void EcP256Sha256Verifier::reset() {
    rut_crypto_ec_workspace_reset_internal(&key, points, values, &scratch);
}

bool EcP256Sha256Verifier::init(const EcP256PublicKey& source) {
    if (key || !source.key) return false;
    const ErrorScope kErrors;
    return rut_crypto_ec_workspace_init_internal(source.key, &key, points, values, &scratch) != 0;
}

bool EcP256Sha256Verifier::verify(Str message, Str signature) {
    if (!valid() || !signature.ptr || signature.len != 64 || (!message.ptr && message.len) ||
        message.len > 1024u * 1024u)
        return false;
    const ErrorScope kErrors;
    return rut_crypto_ec_verify_internal(key,
                                         points,
                                         values,
                                         scratch,
                                         reinterpret_cast<const u8*>(message.ptr),
                                         message.len,
                                         reinterpret_cast<const u8*>(signature.ptr),
                                         signature.len) != 0;
}

bool Es256KeySet::load(Str jwks, const Str* approved_ids, u32 approved_count) {
    if (valid() || !approved_ids || !approved_count || approved_count > kMaxKeys || !jwks.ptr ||
        !jwks.len || jwks.len > EcP256PublicKey::kMaxDerBytes)
        return false;
    for (u32 i = 0; i < approved_count; ++i) {
        if (!approved_ids[i].ptr || !approved_ids[i].len || approved_ids[i].len > kMaxKidBytes)
            return false;
        for (u32 j = 0; j < i; ++j)
            if (approved_ids[i].eq(approved_ids[j])) return false;
    }
    for (u32 i = 0; i < approved_count; ++i) {
        if (!keys[i].load_es256_jwks(jwks, approved_ids[i])) {
            reset();
            return false;
        }
        lengths[i] = approved_ids[i].len;
        __builtin_memcpy(ids[i], approved_ids[i].ptr, approved_ids[i].len);
    }
    count = approved_count;
    return true;
}

void Es256KeySet::reset() {
    count = 0;
    for (u32 i = 0; i < kMaxKeys; ++i) {
        keys[i].reset();
        lengths[i] = 0;
    }
}

bool Es256VerifierSet::init(const Es256KeySet& keys) {
    if (valid() || !keys.valid()) return false;
    for (u32 i = 0; i < keys.count; ++i) {
        if (!verifiers[i].init(keys.keys[i])) {
            reset();
            return false;
        }
        lengths[i] = keys.lengths[i];
        __builtin_memcpy(ids[i], keys.ids[i], lengths[i]);
    }
    count = keys.count;
    return true;
}

void Es256VerifierSet::reset() {
    count = 0;
    for (u32 i = 0; i < Es256KeySet::kMaxKeys; ++i) {
        verifiers[i].reset();
        lengths[i] = 0;
    }
}

Es256VerifierSet::Selection Es256VerifierSet::select(Str kid) {
    if (!kid.ptr || !kid.len || kid.len > Es256KeySet::kMaxKidBytes) return {};
    for (u32 i = 0; i < count; ++i)
        if (kid.eq({ids[i], lengths[i]})) return {&verifiers[i], {ids[i], lengths[i]}};
    return {};
}

}  // namespace rut
