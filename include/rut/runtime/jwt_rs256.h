#pragma once

#include "rut/common/types.h"

namespace rut::json {
struct Document;
}
namespace rut {
class RsaSha256Verifier;

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
}  // namespace rut
