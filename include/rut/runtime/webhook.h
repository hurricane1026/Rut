#pragma once

#include "rut/common/types.h"

namespace rut {
// Bounded native Standard Webhooks symmetric profile. Inputs are singleton
// webhook-id/timestamp/signature field values and the exact raw body. Caller
// rejects duplicate HTTP fields before this API. raw_key is trusted decoded
// secret bytes (not whsec_ serialization), nonempty and <=4096 bytes.
// ID: 1..256 visible ASCII bytes, no '.'; timestamp: canonical positive i64
// decimal seconds. Signature: <=4096 bytes, <=16 single-SP-separated version,
// signature entries, canonical padded Base64 for v1 SHA256 signatures. Unknown
// versions are ignored, never used as algorithms. All entries are validated.
// Body <=1 MiB, including empty/binary. Trusted clock >0; tolerance <=300 seconds
// inclusive on both sides (0 means exact time). No allocation/retained views.
// This authenticates freshness, not uniqueness: caller must deduplicate verified
// IDs durably for side effects and coordinate replay state across shards/nodes.
bool standard_webhook_valid(Str id,
                            Str timestamp,
                            Str signature,
                            Str body,
                            Str raw_key,
                            i64 unix_seconds,
                            u32 tolerance_seconds = 300);
}  // namespace rut
