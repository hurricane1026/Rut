#include "rut/runtime/jwt_es256.h"

#include "rut/common/types.h"
#include "rut/runtime/ec_public_key.h"
#include "rut/runtime/json.h"
#include "rut/runtime/jwt_claims.h"

namespace rut {
namespace {
bool decode(Str in, char* out, u32 capacity, u32& length) {
    length = 0;
    if (in.len % 4 == 1) return false;
    u32 accumulator = 0;
    u32 bits = 0;
    for (u32 i = 0; i < in.len; ++i) {
        const char kC = in.ptr[i];
        u32 value = 0;
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
            if (length == capacity) return false;
            out[length++] = static_cast<char>((accumulator >> bits) & 255);
        }
    }
    return bits == 0 || (accumulator & ((1u << bits) - 1)) == 0;
}
struct Publication {
    json::Document& document;
    bool committed = false;
    ~Publication() {
        if (!committed) {
            document.source = {};
            document.count = 0;
            document.valid = false;
        }
    }
};
bool decode_with_key(EcP256Sha256Verifier* verifier,
                     Es256VerifierSet* keys,
                     json::Document& document,
                     Str token,
                     char* payload_out,
                     u32 capacity,
                     u32& payload_len,
                     Str& selected_kid) {
    payload_len = 0;
    selected_kid = {};
    Publication publication{document};
    if ((verifier == nullptr) == (keys == nullptr) || (verifier && !verifier->valid()) ||
        (keys && !keys->valid()) || !token.ptr || !payload_out || token.len > json::kMaxBytes * 3)
        return false;
    u32 first = token.len;
    u32 second = token.len;
    for (u32 i = 0; i < token.len; ++i) {
        if (token.ptr[i] != '.') continue;
        if (first == token.len)
            first = i;
        else if (second == token.len)
            second = i;
        else
            return false;
    }
    if (first == 0 || first == token.len || second <= first + 1 || second >= token.len - 1)
        return false;
    char header[1024];
    u32 length = 0;
    if (!decode({token.ptr, first}, header, sizeof(header), length) ||
        !document.parse({header, length}) || document.nodes[0].kind != json::Kind::Object)
        return false;
    bool has_algorithm = false;
    bool has_kid = false;
    char kid[Es256KeySet::kMaxKidBytes];
    u32 kid_length = 0;
    for (u32 node = document.nodes[0].child; node != json::kNone;
         node = document.nodes[node].next) {
        json::Writer key{document.scratch};
        if (!document.string(document.nodes[node].key, key)) return false;
        const Str kName{document.scratch, key.len};
        if (kName.eq(lit_str("crit")) || kName.eq(lit_str("b64"))) return false;
        if (keys && kName.eq(lit_str("kid"))) {
            if (has_kid || document.nodes[node].kind != json::Kind::String) return false;
            json::Writer value{kid, sizeof(kid)};
            if (!document.string(node, value) || value.len == 0) return false;
            kid_length = value.len;
            has_kid = true;
        }
        if (!kName.eq(lit_str("alg"))) continue;
        if (has_algorithm || document.nodes[node].kind != json::Kind::String) return false;
        json::Writer value{document.other};
        if (!document.string(node, value) || !Str{document.other, value.len}.eq(lit_str("ES256")))
            return false;
        has_algorithm = true;
    }
    if (!has_algorithm) return false;
    Str candidate_id{};
    if (keys) {
        if (!has_kid) return false;
        auto selected = keys->select({kid, kid_length});
        if (!selected.verifier) return false;
        verifier = selected.verifier;
        candidate_id = selected.kid;
    }
    char signature[64];
    if (!decode({token.ptr + second + 1, token.len - second - 1},
                signature,
                sizeof(signature),
                length) ||
        !verifier->verify({token.ptr, second}, {signature, length}))
        return false;
    const u32 kLimit = capacity < json::kMaxBytes ? capacity : json::kMaxBytes;
    if (!decode({token.ptr + first + 1, second - first - 1}, payload_out, kLimit, length) ||
        !document.parse({payload_out, length}) || document.nodes[0].kind != json::Kind::Object)
        return false;
    payload_len = length;
    selected_kid = candidate_id;
    publication.committed = true;
    return true;
}
}  // namespace

bool jwt_es256_decode(EcP256Sha256Verifier& verifier,
                      json::Document& document,
                      Str token,
                      char* payload_out,
                      u32 capacity,
                      u32& payload_len) {
    Str ignored;
    return decode_with_key(
        &verifier, nullptr, document, token, payload_out, capacity, payload_len, ignored);
}

bool jwt_es256_validate(EcP256Sha256Verifier& verifier,
                        json::Document& document,
                        Str token,
                        Str issuer,
                        Str audience,
                        i64 unix_seconds,
                        char* payload_out,
                        u32 capacity,
                        u32& payload_len) {
    payload_len = 0;
    Publication publication{document};
    if (!issuer.ptr || issuer.len == 0 || !audience.ptr || audience.len == 0 || unix_seconds <= 0)
        return false;
    u32 decoded_length = 0;
    if (!jwt_es256_decode(verifier, document, token, payload_out, capacity, decoded_length) ||
        !jwt_claims_valid(document, {payload_out, decoded_length}, issuer, audience, unix_seconds))
        return false;
    payload_len = decoded_length;
    publication.committed = true;
    return true;
}
bool jwt_es256_validate_set(Es256VerifierSet& keys,
                            json::Document& document,
                            Str token,
                            Str issuer,
                            Str audience,
                            i64 unix_seconds,
                            char* payload_out,
                            u32 capacity,
                            u32& payload_len,
                            Str& verified_kid) {
    payload_len = 0;
    verified_kid = {};
    Publication publication{document};
    if (!issuer.ptr || issuer.len == 0 || !audience.ptr || audience.len == 0 || unix_seconds <= 0)
        return false;
    u32 decoded_length = 0;
    Str selected_id;
    if (!decode_with_key(
            nullptr, &keys, document, token, payload_out, capacity, decoded_length, selected_id) ||
        !jwt_claims_valid(document, {payload_out, decoded_length}, issuer, audience, unix_seconds))
        return false;
    payload_len = decoded_length;
    verified_kid = selected_id;
    publication.committed = true;
    return true;
}
}  // namespace rut
