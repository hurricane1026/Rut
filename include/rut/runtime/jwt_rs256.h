#pragma once

#include "rut/common/types.h"

namespace rut::json {
struct Document;
}
namespace rut {
class RsaSha256Verifier;
class Rs256VerifierSet;

// Fixed-key compact JWS profile: RS256 only, canonical unpadded base64url,
// object header <=1024 bytes and claims <=8192 bytes. Rejects crit and b64
// extensions; key-selection headers never select a key. Caller selects a trusted
// verifier initialized on this shard. No clock/issuer/audience policy here:
// apply jwt_claims_valid before authorization. No allocations or retained token
// views. On success document borrows payload_out; on failure payload_len is zero
// and document is invalid. Output bytes on failure are unspecified. Output must
// not overlap token or document. All workspace belongs to the calling shard.
bool jwt_rs256_decode(RsaSha256Verifier& verifier,
                      json::Document& document,
                      Str token,
                      char* payload_out,
                      u32 capacity,
                      u32& payload_len);

// Decode and apply the strict jwt_claims_valid resource-server profile before
// publishing claims: nonempty subject, exact trusted issuer/audience, required
// integer expiry, optional nbf/iat, positive caller-supplied Unix seconds and
// zero clock skew. Does not enforce scopes, revocation or replay policy.
// Same workspace/lifetime/non-overlap contract as decode; issuer and audience
// must also not alias payload_out or document. Every failure sets payload_len
// to zero and invalidates document; output bytes remain unspecified.
bool jwt_rs256_validate(RsaSha256Verifier& verifier,
                        json::Document& document,
                        Str token,
                        Str issuer,
                        Str audience,
                        i64 unix_seconds,
                        char* payload_out,
                        u32 capacity,
                        u32& payload_len);
// Required protected-header kid selects ONLY an explicitly approved key in an
// already-activated shard-local set. Exact decoded ID bytes, 1..128 bytes; no
// default key, algorithm fallback, token-supplied key import or URL fetching.
// All approved keys must belong to the caller's configured issuer/audience trust
// policy. Applies the same signature and claims profile as jwt_rs256_validate.
// On success verified_kid borrows the canonical configuration ID from keys;
// its lifetime ends at keys.reset()/destruction. On every failure it is empty,
// payload_len is zero and document invalid. Other workspace/alias rules above
// apply; output parameters must not alias each other or the input workspaces.
bool jwt_rs256_validate_set(Rs256VerifierSet& keys,
                            json::Document& document,
                            Str token,
                            Str issuer,
                            Str audience,
                            i64 unix_seconds,
                            char* payload_out,
                            u32 capacity,
                            u32& payload_len,
                            Str& verified_kid);
}  // namespace rut
