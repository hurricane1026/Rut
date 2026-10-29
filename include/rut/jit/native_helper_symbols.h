#pragma once

#include "rut/common/types.h"

// Shared explicit allowlist for ORC and the native artifact symbol resolver.
// Adding a helper requires an explicit entry; arbitrary process symbols are
// never made available through this registry.
#define RUT_NATIVE_HELPER_SYMBOLS(X)            \
    X(rut_helper_req_path)                      \
    X(rut_helper_req_path_only)                 \
    X(rut_helper_req_body)                      \
    X(rut_helper_req_http_version)              \
    X(rut_helper_req_flag)                      \
    X(rut_helper_req_method)                    \
    X(rut_helper_req_header_count)              \
    X(rut_helper_req_unique_header)             \
    X(rut_helper_req_header)                    \
    X(rut_helper_req_set_path)                  \
    X(rut_helper_req_set_load_balance)          \
    X(rut_helper_req_set_target_transform)      \
    X(rut_helper_req_set_header)                \
    X(rut_helper_req_set_owned_header)          \
    X(rut_helper_req_add_header)                \
    X(rut_helper_req_remove_header)             \
    X(rut_helper_resp_set_header)               \
    X(rut_helper_resp_set_optional_header)      \
    X(rut_helper_resp_add_header)               \
    X(rut_helper_resp_remove_header)            \
    X(rut_helper_resp_commit_headers)           \
    X(rut_helper_resp_header)                   \
    X(rut_helper_req_cookie)                    \
    X(rut_helper_req_query)                     \
    X(rut_helper_req_query_string)              \
    X(rut_helper_req_param)                     \
    X(rut_helper_req_remote_addr)               \
    X(rut_helper_req_content_length)            \
    X(rut_helper_parse_prime)                   \
    X(rut_helper_parse_unprime)                 \
    X(rut_helper_hash)                          \
    X(rut_crypto_digest_v1)                     \
    X(rut_crypto_digest_hex_v1)                 \
    X(rut_crypto_digest_parts_v1)               \
    X(rut_crypto_standard_webhook_valid_v1)     \
    X(rut_crypto_standard_webhook_now_v1)       \
    X(rut_crypto_hmac_long_key_v1)              \
    X(rut_crypto_equal_v1)                      \
    X(rut_crypto_equal_bounded_v1)              \
    X(rut_crypto_hmac_sha256_matches_v1)        \
    X(rut_crypto_clear_v1)                      \
    X(rut_crypto_base64_encode_v1)              \
    X(rut_crypto_rsa_key_size_v1)               \
    X(rut_crypto_rsa_key_align_v1)              \
    X(rut_crypto_rsa_key_init_v1)               \
    X(rut_crypto_rsa_key_destroy_v1)            \
    X(rut_crypto_rsa_key_load_der_v1)           \
    X(rut_crypto_rsa_key_load_jwk_v1)           \
    X(rut_crypto_rsa_key_load_jwks_v1)          \
    X(rut_crypto_rsa_verifier_size_v1)          \
    X(rut_crypto_rsa_verifier_align_v1)         \
    X(rut_crypto_rsa_verifier_init_v1)          \
    X(rut_crypto_rsa_verifier_destroy_v1)       \
    X(rut_crypto_rsa_verify_sha256_v1)          \
    X(rut_crypto_rsa_key_set_size_v1)           \
    X(rut_crypto_rsa_key_set_align_v1)          \
    X(rut_crypto_rsa_key_set_init_v1)           \
    X(rut_crypto_rsa_key_set_destroy_v1)        \
    X(rut_crypto_rsa_key_set_load_v1)           \
    X(rut_crypto_rsa_verifier_set_size_v1)      \
    X(rut_crypto_rsa_verifier_set_align_v1)     \
    X(rut_crypto_rsa_verifier_set_init_v1)      \
    X(rut_crypto_rsa_verifier_set_destroy_v1)   \
    X(rut_crypto_rsa_verifier_set_select_v1)    \
    X(rut_crypto_rsa_verifier_set_select_id_v1) \
    X(rut_helper_uuid)                          \
    X(rut_helper_str_has_prefix)                \
    X(rut_helper_http_origin_list_allows)       \
    X(rut_helper_http_token_list_allows)        \
    X(rut_helper_bearer_matches)                \
    X(rut_helper_standard_webhook_valid)        \
    X(rut_helper_hmac_sha256_matches)           \
    X(rut_helper_basic_matches)                 \
    X(rut_helper_str_constant_time_equal)       \
    X(rut_helper_str_eq)                        \
    X(rut_helper_str_cmp)                       \
    X(rut_helper_str_regex_match)               \
    X(rut_helper_str_trim_prefix)               \
    X(rut_helper_resp_body)                     \
    X(rut_helper_json)                          \
    X(rut_helper_cache_get)                     \
    X(rut_helper_cache_set)                     \
    X(rut_helper_time_now_micros)               \
    X(rut_helper_time_unlatch)

namespace rut {
struct NativeHelperSymbol {
    const char* name;
    void* address;
};
const NativeHelperSymbol* native_helper_symbols(u32& count);
void* find_native_helper(Str name);
}  // namespace rut
