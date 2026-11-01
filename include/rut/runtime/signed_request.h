#pragma once

#include "rut/common/types.h"

namespace rut {

// Verify the fixed native signed-request profile documented in
// docs/auth-coverage.md. Inputs are already-selected singleton fields; callers
// are responsible for rejecting duplicate HTTP fields before calling this API.
// The Authorization value must have this form (the four parameters may appear
// in any order):
//   Signature keyId="...",algorithm="hmac-sha256",
//     headers="@request-target date digest",signature="..."
// The signature covers trusted_key_id, the uppercase method and exact
// origin-form target, the supplied canonical IMF-fixdate, and the supplied
// canonical SHA-256 digest. Body and key sizes are bounded; the function does
// not allocate or retain input pointers. unix_seconds is the caller's trusted
// current UTC epoch time.
bool signed_request_hmac_sha256_valid(Str method,
                                      Str request_target,
                                      Str authorization,
                                      Str date,
                                      Str digest,
                                      Str raw_body,
                                      Str trusted_key_id,
                                      Str trusted_secret,
                                      i64 unix_seconds);

}  // namespace rut
