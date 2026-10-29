#include "rut/runtime/webhook.h"

#include "rut/runtime/crypto_c.h"

namespace rut {
bool standard_webhook_valid(Str id,
                            Str timestamp,
                            Str signature,
                            Str body,
                            Str raw_key,
                            i64 unix_seconds,
                            u32 tolerance_seconds) {
    const rut_crypto_span_v1 kId{reinterpret_cast<const u8*>(id.ptr), id.len};
    const rut_crypto_span_v1 kTimestamp{reinterpret_cast<const u8*>(timestamp.ptr), timestamp.len};
    const rut_crypto_span_v1 kSignature{reinterpret_cast<const u8*>(signature.ptr), signature.len};
    const rut_crypto_span_v1 kBody{reinterpret_cast<const u8*>(body.ptr), body.len};
    const rut_crypto_span_v1 kKey{reinterpret_cast<const u8*>(raw_key.ptr), raw_key.len};
    return rut_crypto_standard_webhook_valid_v1(
               &kId, &kTimestamp, &kSignature, &kBody, &kKey, unix_seconds, tolerance_seconds) != 0;
}
}  // namespace rut
