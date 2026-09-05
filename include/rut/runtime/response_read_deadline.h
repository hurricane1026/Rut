#pragma once

#include "rut/common/request_policy.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/http_parser.h"
#include "rut/runtime/route_table.h"

#include <netinet/in.h>

namespace rut {

// Pure millisecond rounding used when a precise timeout CQE arrives before
// its logical deadline. A zero result means the deadline is due now.
inline u32 response_read_timer_remaining_ms(u64 last_progress_ns, u64 timeout_ns, u64 now_ns) {
    if (last_progress_ns == 0 || timeout_ns > UINT64_MAX - last_progress_ns ||
        now_ns >= last_progress_ns + timeout_ns)
        return 0;
    const u64 remaining_ns = last_progress_ns + timeout_ns - now_ns;
    u64 remaining_ms = (remaining_ns + 999'999ull) / 1'000'000ull;
    if (remaining_ms == 0) remaining_ms = 1;
    return remaining_ms > UINT32_MAX ? UINT32_MAX : static_cast<u32>(remaining_ms);
}

inline bool response_read_deadline_http_date_is_normalized(Str value) {
    if (value.ptr == nullptr || value.len != 29 || value.ptr[3] != ',' || value.ptr[4] != ' ' ||
        value.ptr[7] != ' ' || value.ptr[11] != ' ' || value.ptr[16] != ' ' ||
        value.ptr[19] != ':' || value.ptr[22] != ':' || value.ptr[25] != ' ' ||
        __builtin_memcmp(value.ptr + 26, "GMT", 3) != 0)
        return false;
    static constexpr const char* kWeekdays[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static constexpr const char* kMonths[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    bool weekday = false;
    for (const char* token : kWeekdays) {
        if (__builtin_memcmp(value.ptr, token, 3) == 0) {
            weekday = true;
            break;
        }
    }
    bool month = false;
    for (const char* token : kMonths) {
        if (__builtin_memcmp(value.ptr + 8, token, 3) == 0) {
            month = true;
            break;
        }
    }
    if (!weekday || !month) return false;
    for (u32 i : {5u, 6u, 12u, 13u, 14u, 15u, 17u, 18u, 20u, 21u, 23u, 24u}) {
        if (value.ptr[i] < '0' || value.ptr[i] > '9') return false;
    }
    return true;
}

enum class ResponseReadDeadlineOwnerPhase : u8 {
    ValidatedBeforeArm,
    ArmedForCopy,
    ActiveAfterCopy
};

inline bool response_read_deadline_non_head_method_admitted(u8 method) {
    switch (static_cast<LogHttpMethod>(method)) {
        case LogHttpMethod::Get:
        case LogHttpMethod::Post:
        case LogHttpMethod::Put:
        case LogHttpMethod::Delete:
        case LogHttpMethod::Patch:
        case LogHttpMethod::Options:
        case LogHttpMethod::Trace:
            return true;
        case LogHttpMethod::Head:
        case LogHttpMethod::Connect:
        case LogHttpMethod::Other:
            return false;
    }
    return false;
}

inline bool response_read_deadline_fixed_upload_method_admitted(
    u8 method, ForwardResponseBufferingMode buffering) {
    if (!forward_response_buffering_mode_valid(buffering)) return false;
    switch (static_cast<LogHttpMethod>(method)) {
        case LogHttpMethod::Get:
        case LogHttpMethod::Post:
        case LogHttpMethod::Put:
        case LogHttpMethod::Patch:
            return true;
        case LogHttpMethod::Delete:
        case LogHttpMethod::Options:
            return buffering == ForwardResponseBufferingMode::CompleteContentLength;
        case LogHttpMethod::Head:
        case LogHttpMethod::Trace:
        case LogHttpMethod::Connect:
        case LogHttpMethod::Other:
            return false;
    }
    return false;
}

inline bool response_read_deadline_fixed_upload_profile_method_admitted(
    ResponseReadDeadlineProfile profile, u8 method, ForwardResponseBufferingMode buffering) {
    switch (profile) {
        case ResponseReadDeadlineProfile::FixedContentLengthUploadNonHeadContentLengthZero:
            return response_read_deadline_fixed_upload_method_admitted(method, buffering);
        case ResponseReadDeadlineProfile::FixedContentLengthUploadHeaderOnlyHead:
            return buffering == ForwardResponseBufferingMode::None &&
                   static_cast<LogHttpMethod>(method) == LogHttpMethod::Head;
        case ResponseReadDeadlineProfile::None:
        case ResponseReadDeadlineProfile::HeaderOnlyHead:
        case ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero:
            return false;
    }
    return false;
}

inline bool response_read_deadline_route_method_matches(u8 method, u8 route_method);

inline bool complete_content_length_response_status_is_admitted(u16 status) {
    return status == 200 || status == 201;
}

struct CompleteContentLengthContentTypeView {
    u32 count = 0;
    Str value{};
};

inline bool complete_content_length_content_type_view(const ParsedResponse& response,
                                                      bool require_canonical,
                                                      CompleteContentLengthContentTypeView* out) {
    if (out == nullptr) return false;
    *out = {};
    static constexpr char kName[] = "Content-Type";
    for (u32 i = 0; i < response.header_count; ++i) {
        const Header& header = response.headers[i];
        if (!http_header_name_eq_ci(header.name.ptr, header.name.len, kName, sizeof(kName) - 1u))
            continue;
        if (++out->count > 1 || !response_policy_safe_content_type(header.value)) return false;
        if (require_canonical &&
            (header.name.len != sizeof(kName) - 1u ||
             __builtin_memcmp(header.name.ptr, kName, sizeof(kName) - 1u) != 0 ||
             header.raw_value.len != header.value.len + 1u || header.raw_value.ptr[0] != ' ' ||
             __builtin_memcmp(header.raw_value.ptr + 1, header.value.ptr, header.value.len) != 0))
            return false;
        out->value = header.value;
    }
    return true;
}

inline bool complete_content_length_pinned_header_matches(const Connection& c, u32 declared_body) {
    if (c.request_config == nullptr ||
        !c.request_config->response_policy_id_is_valid(c.response_policy_id) ||
        c.response_header_buf.data() == nullptr || c.response_header_buf.len() == 0)
        return false;
    HttpResponseParser parser;
    ParsedResponse parsed;
    parser.reset();
    parsed.reset();
    if (parser.parse(c.response_header_buf.data(), c.response_header_buf.len(), &parsed) !=
            ParseStatus::Complete ||
        parser.header_end != c.response_header_buf.len() || parsed.version != HttpVersion::Http11 ||
        !complete_content_length_response_status_is_admitted(parsed.status_code) ||
        parsed.status_code != c.resp_status || parsed.content_length_count != 1 || parsed.chunked ||
        parsed.headers_truncated || parsed.content_length != declared_body)
        return false;
    const auto& policy = c.request_config->response_policies[c.response_policy_id - 1];
    CompleteContentLengthContentTypeView content_type{};
    if (!complete_content_length_content_type_view(parsed, true, &content_type)) return false;
    static constexpr Str kContentTypeName{"Content-Type", 12};
    if (response_policy_hides_header(policy, kContentTypeName) && content_type.count != 0)
        return false;
    u32 server_count = 0;
    u32 connection_count = 0;
    for (u32 i = 0; i < parsed.header_count; ++i) {
        const Header& header = parsed.headers[i];
        if (http_header_name_eq_ci(header.name.ptr, header.name.len, "server", 6)) {
            ++server_count;
            if (header.value.len != policy.server.len ||
                (policy.server.len != 0 &&
                 __builtin_memcmp(header.value.ptr, policy.server.ptr, policy.server.len) != 0))
                return false;
        } else if (http_header_name_eq_ci(header.name.ptr, header.name.len, "connection", 10)) {
            ++connection_count;
            static constexpr char kKeepAlive[] = "keep-alive";
            static constexpr char kClose[] = "close";
            const char* expected =
                c.response_read_deadline_upload.downstream_close ? kClose : kKeepAlive;
            const u32 expected_len = c.response_read_deadline_upload.downstream_close
                                         ? sizeof(kClose) - 1u
                                         : sizeof(kKeepAlive) - 1u;
            if (header.value.len != expected_len ||
                __builtin_memcmp(header.value.ptr, expected, expected_len) != 0)
                return false;
        }
    }
    return server_count == 1 && connection_count == 1;
}

inline bool complete_content_length_raw_origin_matches_pinned(const Connection& c,
                                                              u32 raw_header_end,
                                                              u32 declared_body) {
    if (raw_header_end == 0 || raw_header_end > c.upstream_recv_buf.len() ||
        !complete_content_length_pinned_header_matches(c, declared_body))
        return false;

    HttpResponseParser raw_parser;
    ParsedResponse raw;
    raw_parser.reset();
    raw.reset();
    if (raw_parser.parse(c.upstream_recv_buf.data(), raw_header_end, &raw) !=
            ParseStatus::Complete ||
        raw_parser.header_end != raw_header_end || raw.version != HttpVersion::Http11 ||
        !complete_content_length_response_status_is_admitted(raw.status_code) ||
        raw.status_code != c.resp_status || raw.content_length_count != 1 ||
        !raw.has_content_length || raw.chunked || raw.headers_truncated ||
        raw.content_length != declared_body)
        return false;

    HttpResponseParser pinned_parser;
    ParsedResponse pinned;
    pinned_parser.reset();
    pinned.reset();
    if (pinned_parser.parse(c.response_header_buf.data(), c.response_header_buf.len(), &pinned) !=
            ParseStatus::Complete ||
        pinned_parser.header_end != c.response_header_buf.len() ||
        raw.status_code != pinned.status_code || raw.reason.len != pinned.reason.len ||
        (raw.reason.len != 0 &&
         __builtin_memcmp(raw.reason.ptr, pinned.reason.ptr, raw.reason.len) != 0))
        return false;
    CompleteContentLengthContentTypeView raw_content_type{};
    CompleteContentLengthContentTypeView pinned_content_type{};
    if (!complete_content_length_content_type_view(raw, false, &raw_content_type) ||
        !complete_content_length_content_type_view(pinned, true, &pinned_content_type))
        return false;
    const auto& policy = c.request_config->response_policies[c.response_policy_id - 1];
    static constexpr Str kContentTypeName{"Content-Type", 12};
    if (response_policy_hides_header(policy, kContentTypeName))
        return pinned_content_type.count == 0;
    if (raw_content_type.count != pinned_content_type.count) return false;
    return raw_content_type.count == 0 ||
           (raw_content_type.value.len == pinned_content_type.value.len &&
            __builtin_memcmp(raw_content_type.value.ptr,
                             pinned_content_type.value.ptr,
                             raw_content_type.value.len) == 0);
}

inline bool complete_content_length_pinned_header_is_stable(const Connection& c) {
    return complete_content_length_pinned_header_matches(
        c, c.response_read_deadline_post_commit_declared_body);
}

inline bool response_read_deadline_upload_proof_equal(const ResponseReadDeadlineUploadProof& a,
                                                      const ResponseReadDeadlineUploadProof& b) {
    return a.handler_generation == b.handler_generation && a.raw_header_end == b.raw_header_end &&
           a.raw_content_length == b.raw_content_length &&
           a.raw_total_length == b.raw_total_length &&
           a.rewritten_header_end == b.rewritten_header_end &&
           a.rewritten_total_length == b.rewritten_total_length &&
           a.upload_episode == b.upload_episode &&
           a.expected_upload_length == b.expected_upload_length && a.route_index == b.route_index &&
           a.upstream_id == b.upstream_id && a.request_policy_id == b.request_policy_id &&
           a.route_fn == b.route_fn && a.downstream_close == b.downstream_close;
}

inline bool response_read_deadline_default_persistence_is_stable(const Connection& c) {
    return c.req_keep_alive && c.req_client_keep_alive && !c.req_client_connection_close &&
           !c.req_client_connection_close_exact && c.req_client_connection_count == 0;
}

inline bool complete_content_length_explicit_close_request_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& proof,
    ForwardResponseBufferingMode buffering,
    ResponseReadDeadlineProfile profile) {
    if (!proof.downstream_close ||
        buffering != ForwardResponseBufferingMode::CompleteContentLength ||
        profile != ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero ||
        c.req_client_keep_alive || !c.req_client_connection_close ||
        !c.req_client_connection_close_exact || c.req_client_connection_count != 1)
        return false;
    if (proof.request_policy_id == 0) return !c.req_keep_alive;
    return proof.request_policy_id == static_cast<u16>(RequestPolicyId::Http11FixedStrip) &&
           c.req_keep_alive;
}

inline bool complete_content_length_explicit_close_is_stable(
    const Connection& c, const ResponseReadDeadlineUploadProof& proof) {
    return complete_content_length_explicit_close_request_is_stable(
        c, proof, c.response_read_deadline_buffering, c.response_read_deadline_profile);
}

inline bool header_only_head_explicit_close_is_stable(
    const Connection& c, const ResponseReadDeadlineUploadProof& proof) {
    return proof.downstream_close &&
           c.response_read_deadline_profile == ResponseReadDeadlineProfile::HeaderOnlyHead &&
           c.response_read_deadline_buffering == ForwardResponseBufferingMode::None &&
           c.response_read_deadline_method == static_cast<u8>(LogHttpMethod::Head) &&
           c.req_method == c.response_read_deadline_method && c.req_keep_alive &&
           !c.req_client_keep_alive && c.req_client_connection_close &&
           c.req_client_connection_close_exact && c.req_client_connection_count == 1 &&
           c.pipeline_depth == 0 && c.http1_pipeline_request_generation == 0 &&
           c.request_policy_id == static_cast<u16>(RequestPolicyId::Http11FixedStrip) &&
           proof.request_policy_id == c.request_policy_id;
}

// After a rewritten HeaderOnlyHead request has been sent, recv_buf is released
// and the ordinary generation proof cannot recover the original route/request
// identity.  Keep a separate, post-send proof for this explicit-close shape;
// it is intentionally exact and does not relax any other deadline profile.
inline bool header_only_head_explicit_close_arm_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& proof,
    const RouteConfig* config,
    u16 bundle_id,
    ResponseReadDeadlineOwnerPhase phase,
    Connection::Callback expected_upstream_recv) {
    if (config == nullptr || config != c.request_config ||
        !config->policy_bundle_id_is_valid(bundle_id) ||
        (phase == ResponseReadDeadlineOwnerPhase::ValidatedBeforeArm &&
         c.response_read_deadline_state != ResponseReadDeadlineState::Validated) ||
        c.response_read_deadline_profile != ResponseReadDeadlineProfile::HeaderOnlyHead ||
        c.response_read_deadline_buffering != ForwardResponseBufferingMode::None ||
        c.response_read_deadline_method != static_cast<u8>(LogHttpMethod::Head) ||
        expected_upstream_recv == nullptr || c.req_method != c.response_read_deadline_method ||
        !response_read_deadline_route_method_matches(c.response_read_deadline_method,
                                                     c.response_read_deadline_route_method) ||
        !header_only_head_explicit_close_is_stable(c, proof) ||
        c.response_read_deadline_bundle_id != bundle_id ||
        c.response_read_deadline_owner_generation == 0 ||
        c.response_read_deadline_owner_generation != c.response_read_deadline_generation ||
        proof.handler_generation == 0 || proof.handler_generation != c.handler_gen ||
        proof.route_index >= config->route_count || proof.route_fn == nullptr ||
        proof.upstream_id >= config->upstream_count || proof.upstream_id != c.upstream_idx ||
        !valid_upstream_episode(proof.upload_episode) ||
        proof.upload_episode != c.upstream_episode || proof.raw_header_end == 0 ||
        proof.raw_content_length != 0 || proof.raw_total_length != proof.raw_header_end ||
        proof.rewritten_header_end == 0 || proof.rewritten_header_end != c.req_header_end ||
        proof.rewritten_total_length != c.req_initial_send_len ||
        proof.expected_upload_length != proof.rewritten_total_length ||
        c.protocol != ConnProtocol::Http11 || c.tls_active || c.h2 != nullptr ||
        c.req_http_version != static_cast<u8>(HttpVersion::Http11) || !c.req_strict_h1_complete ||
        c.req_path_canon.ptr == nullptr || c.req_client_content_length_count != 0 ||
        c.req_client_has_content_length || c.req_client_has_transfer_encoding ||
        c.req_client_has_te || c.req_client_has_expect || c.req_client_has_upgrade_header ||
        c.req_malformed || c.req_wants_upgrade || c.req_body_mode != BodyMode::None ||
        c.req_body_remaining != 0 || c.request_body_fully_buffered || c.req_body_streamed ||
        c.pipeline_depth != 0 || c.pipeline_stash_len != 0 || c.retry_req_send_len != 0 ||
        c.response_mutations_snapshotted || c.target_transform_recorded || c.req_path_overridden ||
        c.req_header_override_count != 0 || c.req_header_override_overflow ||
        c.resp_header_mutation_count != 0 || c.resp_header_mutation_pending_count != 0 ||
        c.resp_header_mutation_pending_overflow || c.resp_header_mutation_overflow ||
        !c.response_policy_suppress_body || !c.failure_policy_suppress_body ||
        !c.request_upload_complete || c.upstream_request_incomplete || c.upstream_reused ||
        c.upstream_attempts != 1 || c.upstream_fd < 0 || c.upstream_abandoned ||
        c.upstream_episode_quarantined)
        return false;
    if (phase == ResponseReadDeadlineOwnerPhase::ValidatedBeforeArm) {
        if (c.response_read_deadline_state != ResponseReadDeadlineState::Validated ||
            c.upstream_recv_armed || c.on_upstream_recv != expected_upstream_recv)
            return false;
    } else {
        const bool state_ok =
            phase == ResponseReadDeadlineOwnerPhase::ArmedForCopy
                ? c.response_read_deadline_state == ResponseReadDeadlineState::Armed
                : c.response_read_deadline_state == ResponseReadDeadlineState::Armed ||
                      c.response_read_deadline_state == ResponseReadDeadlineState::ExpiryPending ||
                      c.response_read_deadline_state == ResponseReadDeadlineState::BatchPending ||
                      c.response_read_deadline_state == ResponseReadDeadlineState::RefreshPending;
        if (!state_ok || !c.upstream_recv_armed || c.on_upstream_recv != expected_upstream_recv)
            return false;
    }
    const auto& bundle = config->policy_bundles[bundle_id - 1];
    if (bundle.response_buffering != ForwardResponseBufferingMode::None ||
        bundle.response_policy_id != c.response_policy_id ||
        bundle.failure_policy_id != c.failure_policy_id ||
        bundle.timeout_failure_policy_id != c.timeout_failure_policy_id ||
        !config->response_policy_id_is_valid(bundle.response_policy_id) ||
        !config->failure_policy_id_is_valid(bundle.failure_policy_id) ||
        !config->timeout_failure_policy_id_is_valid(bundle.timeout_failure_policy_id))
        return false;
    const auto& response = config->response_policies[bundle.response_policy_id - 1];
    const auto& failure = config->failure_policies[bundle.failure_policy_id - 1];
    const auto& timeout = config->failure_policies[bundle.timeout_failure_policy_id - 1];
    if (!response_policy_spec_valid(response) || !forward_failure_policy_spec_valid(failure) ||
        !forward_timeout_failure_policy_spec_valid(timeout) ||
        response.version != ResponsePolicyVersion::Http11 ||
        response.framing != ResponsePolicyFraming::ContentLength ||
        response.connection != ResponsePolicyConnection::Request ||
        response.head_mode != ResponsePolicyHeadMode::SuppressBody ||
        failure.version != ForwardFailurePolicyVersion::Http11 || failure.status_code != 502 ||
        failure.connection != ForwardFailurePolicyConnection::Request ||
        failure.head_mode != FailurePolicyHeadMode::SuppressBody ||
        timeout.version != ForwardFailurePolicyVersion::Http11 ||
        timeout.connection != ForwardFailurePolicyConnection::Request ||
        timeout.head_mode != FailurePolicyHeadMode::SuppressBody)
        return false;
    const RouteEntry& route = config->routes[proof.route_index];
    if (route.action != RouteAction::JitHandler || route.fn != proof.route_fn ||
        route.needs_req_body || route.rate_limit.count != 0 || route.throttle_down_bps != 0 ||
        route.ws_terminate ||
        !forward_preflight_mode_can_own_runtime_deadline(route.forward_preflight_mode) ||
        route.preflight_forward_policy_bundle_id != bundle_id ||
        !response_read_deadline_route_method_matches(c.req_method, route.method) ||
        route.method != c.response_read_deadline_route_method)
        return false;
    RouteParam params[kMaxRouteParams]{};
    u32 param_count = 0;
    return config->match_canonical(c.req_path_canon,
                                   route_method_key(static_cast<LogHttpMethod>(c.req_method)),
                                   params,
                                   &param_count,
                                   kMaxRouteParams) == &route;
}

// The timeout D2 copy has to retain the same HeaderOnlyHead admission proof
// after the request buffer and the live upstream owner are handed off. Keep
// this check separate from the generic CompleteContentLength proofs: this
// profile has no request body and its timeout representation is a header-only
// 504 carrying the policy's declared body length.
enum class ResponseReadTimeoutHeaderOnlyHeadPhase : u8 { PreBegin, SendingRetired };

inline bool response_read_timeout_header_only_head_explicit_close_is_stable(
    const Connection& c, const RouteConfig* config, u16 bundle_id) {
    if (config == nullptr || config != c.request_config ||
        !config->policy_bundle_id_is_valid(bundle_id) ||
        c.http1_prebuilt_deadline_profile != ResponseReadDeadlineProfile::HeaderOnlyHead ||
        c.http1_prebuilt_response_purpose != Http1PrebuiltResponsePurpose::ResponseReadTimeout ||
        c.http1_prebuilt_deadline_config != config ||
        c.http1_prebuilt_deadline_bundle_id != bundle_id ||
        c.http1_prebuilt_deadline_generation == 0 ||
        c.http1_prebuilt_deadline_generation != c.response_read_deadline_generation ||
        c.http1_prebuilt_deadline_method != static_cast<u8>(LogHttpMethod::Head) ||
        c.req_method != c.http1_prebuilt_deadline_method ||
        !response_read_deadline_route_method_matches(c.http1_prebuilt_deadline_method,
                                                     c.http1_prebuilt_deadline_route_method) ||
        c.request_policy_id != static_cast<u16>(RequestPolicyId::Http11FixedStrip) ||
        c.http1_prebuilt_deadline_upload.request_policy_id != c.request_policy_id ||
        !c.http1_prebuilt_deadline_upload.downstream_close)
        return false;
    const auto& bundle = config->policy_bundles[bundle_id - 1];
    if (bundle.response_buffering != ForwardResponseBufferingMode::None ||
        bundle.response_policy_id != c.response_policy_id ||
        bundle.failure_policy_id != c.failure_policy_id ||
        bundle.timeout_failure_policy_id != c.timeout_failure_policy_id ||
        !config->response_policy_id_is_valid(bundle.response_policy_id) ||
        !config->failure_policy_id_is_valid(bundle.failure_policy_id) ||
        !config->timeout_failure_policy_id_is_valid(bundle.timeout_failure_policy_id))
        return false;
    return config->response_policies[bundle.response_policy_id - 1].head_mode ==
               ResponsePolicyHeadMode::SuppressBody &&
           config->failure_policies[bundle.failure_policy_id - 1].head_mode ==
               FailurePolicyHeadMode::SuppressBody &&
           config->failure_policies[bundle.timeout_failure_policy_id - 1].head_mode ==
               FailurePolicyHeadMode::SuppressBody;
}

inline bool response_read_timeout_header_only_head_is_stable(const Connection& c,
                                                             const RouteConfig* config,
                                                             u16 bundle_id) {
    if (response_read_timeout_header_only_head_explicit_close_is_stable(c, config, bundle_id))
        return true;
    if (config == nullptr || config != c.request_config ||
        !config->policy_bundle_id_is_valid(bundle_id) ||
        c.http1_prebuilt_deadline_profile != ResponseReadDeadlineProfile::HeaderOnlyHead ||
        c.http1_prebuilt_response_purpose != Http1PrebuiltResponsePurpose::ResponseReadTimeout ||
        c.http1_prebuilt_deadline_config != config ||
        c.http1_prebuilt_deadline_bundle_id != bundle_id ||
        c.http1_prebuilt_deadline_generation == 0 ||
        c.http1_prebuilt_deadline_generation != c.response_read_deadline_generation ||
        c.http1_prebuilt_deadline_method != static_cast<u8>(LogHttpMethod::Head) ||
        c.req_method != c.http1_prebuilt_deadline_method ||
        !response_read_deadline_route_method_matches(c.http1_prebuilt_deadline_method,
                                                     c.http1_prebuilt_deadline_route_method) ||
        c.request_policy_id != static_cast<u16>(RequestPolicyId::Http11FixedStrip) ||
        c.http1_prebuilt_deadline_upload.request_policy_id != c.request_policy_id ||
        c.http1_prebuilt_deadline_upload.downstream_close ||
        !response_read_deadline_default_persistence_is_stable(c))
        return false;
    const auto& bundle = config->policy_bundles[bundle_id - 1];
    if (bundle.response_buffering != ForwardResponseBufferingMode::None ||
        bundle.response_policy_id != c.response_policy_id ||
        bundle.failure_policy_id != c.failure_policy_id ||
        bundle.timeout_failure_policy_id != c.timeout_failure_policy_id ||
        !config->response_policy_id_is_valid(bundle.response_policy_id) ||
        !config->failure_policy_id_is_valid(bundle.failure_policy_id) ||
        !config->timeout_failure_policy_id_is_valid(bundle.timeout_failure_policy_id))
        return false;
    return config->response_policies[bundle.response_policy_id - 1].head_mode ==
               ResponsePolicyHeadMode::SuppressBody &&
           config->failure_policies[bundle.failure_policy_id - 1].head_mode ==
               FailurePolicyHeadMode::SuppressBody &&
           config->failure_policies[bundle.timeout_failure_policy_id - 1].head_mode ==
               FailurePolicyHeadMode::SuppressBody;
}

inline bool response_read_timeout_header_only_head_response_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& copied_proof,
    const RouteConfig* config,
    u16 bundle_id,
    u32 expected_generation,
    ResponseReadTimeoutHeaderOnlyHeadPhase phase) {
    if (config == nullptr || config != c.request_config ||
        !config->policy_bundle_id_is_valid(bundle_id) ||
        c.http1_prebuilt_deadline_profile != ResponseReadDeadlineProfile::HeaderOnlyHead ||
        c.http1_prebuilt_deadline_method != static_cast<u8>(LogHttpMethod::Head) ||
        c.req_method != c.http1_prebuilt_deadline_method ||
        !response_read_deadline_route_method_matches(c.req_method,
                                                     c.http1_prebuilt_deadline_route_method) ||
        c.http1_prebuilt_deadline_bundle_id != bundle_id ||
        c.http1_prebuilt_deadline_generation == 0 || c.pipeline_depth != 0 ||
        c.http1_pipeline_request_generation != 0 || c.protocol != ConnProtocol::Http11 ||
        c.tls_active || c.h2 != nullptr ||
        c.req_http_version != static_cast<u8>(HttpVersion::Http11) || !c.req_strict_h1_complete ||
        c.req_path_canon.ptr == nullptr || c.req_client_content_length_count != 0 ||
        c.req_client_has_content_length || c.req_client_has_transfer_encoding ||
        c.req_client_has_te || c.req_client_has_expect || c.req_client_has_upgrade_header ||
        c.req_malformed || c.req_wants_upgrade || c.req_upgrade_is_websocket ||
        c.resp_upgrade_is_websocket || c.req_body_mode != BodyMode::None ||
        c.req_body_remaining != 0 || c.request_body_fully_buffered || c.req_body_streamed ||
        c.pipeline_stash_len != 0 || c.retry_req_send_len != 0 ||
        c.response_mutations_snapshotted || c.target_transform_recorded || c.req_path_overridden ||
        c.req_header_override_count != 0 || c.req_header_override_overflow ||
        c.resp_header_mutation_count != 0 || c.resp_header_mutation_pending_count != 0 ||
        c.resp_header_mutation_pending_overflow || c.resp_header_mutation_overflow ||
        !c.request_upload_complete || c.upstream_request_incomplete || c.upstream_reused ||
        c.upstream_attempts != 1 || !c.req_keep_alive ||
        c.request_policy_id != static_cast<u16>(RequestPolicyId::Http11FixedStrip) ||
        c.http1_prebuilt_response_purpose != Http1PrebuiltResponsePurpose::ResponseReadTimeout ||
        c.http1_prebuilt_response_layout != Http1PrebuiltResponseLayout::HeaderOnlyHead ||
        c.http1_prebuilt_deadline_profile != ResponseReadDeadlineProfile::HeaderOnlyHead ||
        c.http1_prebuilt_deadline_method != static_cast<u8>(LogHttpMethod::Head) ||
        !response_read_deadline_route_method_matches(c.http1_prebuilt_deadline_method,
                                                     c.http1_prebuilt_deadline_route_method) ||
        c.http1_prebuilt_deadline_bundle_id != bundle_id ||
        c.http1_prebuilt_deadline_generation != expected_generation ||
        c.http1_prebuilt_deadline_config != config ||
        !response_read_deadline_upload_proof_equal(c.http1_prebuilt_deadline_upload,
                                                   copied_proof) ||
        c.http1_prebuilt_header_end == 0 ||
        c.http1_prebuilt_total_len != c.http1_prebuilt_header_end ||
        c.http1_prebuilt_total_len != c.response_header_buf.len() ||
        c.http1_prebuilt_body_len == 0 || c.http1_prebuilt_status != 504 || c.resp_status != 504 ||
        c.resp_body_mode != BodyMode::None || c.resp_body_remaining != 0 ||
        c.upstream_send_len != 0 || c.response_header_buf.data() == nullptr)
        return false;
    const bool explicit_close = copied_proof.downstream_close && !c.req_client_keep_alive &&
                                c.req_client_connection_close &&
                                c.req_client_connection_close_exact &&
                                c.req_client_connection_count == 1;
    const bool default_keep_alive =
        !copied_proof.downstream_close && response_read_deadline_default_persistence_is_stable(c);
    if (!explicit_close && !default_keep_alive) return false;
    if (phase != ResponseReadTimeoutHeaderOnlyHeadPhase::PreBegin &&
        phase != ResponseReadTimeoutHeaderOnlyHeadPhase::SendingRetired)
        return false;
    if (phase == ResponseReadTimeoutHeaderOnlyHeadPhase::PreBegin) {
        if (c.state != ConnState::Proxying ||
            c.http1_prebuilt_disposition != Http1RequestBufferDisposition::None ||
            c.http1_prebuilt_request_prefix_len != 0 || c.resp_body_sent != 0)
            return false;
    } else if (c.state != ConnState::Sending ||
               c.http1_prebuilt_disposition != Http1RequestBufferDisposition::ExistingPipeline ||
               c.resp_body_sent != c.http1_prebuilt_total_len ||
               c.resp_body_sent != c.http1_prebuilt_header_end || c.upstream_fd >= 0 ||
               !c.upstream_abandoned ||
               copied_proof.upload_episode != c.upstream_retiring_episode ||
               !valid_upstream_episode(copied_proof.upload_episode) ||
               !valid_upstream_episode(c.upstream_episode) ||
               c.upstream_retiring_episode >= c.upstream_episode || c.upstream_recv_armed ||
               c.on_upstream_recv != nullptr || c.on_upstream_send != nullptr)
        return false;
    if (phase == ResponseReadTimeoutHeaderOnlyHeadPhase::SendingRetired) {
        const u8 target = c.upstream_retirement_target_owned;
        const u8 cancel = c.upstream_retirement_cancel_owned;
        const u8 retry = c.upstream_retirement_cancel_retry;
        const u8 recv = kUpstreamOpRecv;
        const bool ledger_active = c.upstream_retirement_active &&
                                   (target | cancel | retry) == recv &&
                                   (retry & static_cast<u8>(~target)) == 0 && (cancel & retry) == 0;
        const bool ledger_drained =
            !c.upstream_retirement_active && c.upstream_retirement_target_owned == 0 &&
            c.upstream_retirement_cancel_owned == 0 && c.upstream_retirement_cancel_retry == 0;
        if (!ledger_active && !ledger_drained) return false;
    }
    const auto& bundle = config->policy_bundles[bundle_id - 1];
    if (bundle.response_buffering != ForwardResponseBufferingMode::None ||
        bundle.response_policy_id != c.response_policy_id ||
        bundle.failure_policy_id != c.failure_policy_id ||
        bundle.timeout_failure_policy_id != c.timeout_failure_policy_id ||
        !response_read_timeout_seconds_valid(bundle.response_read_timeout_seconds) ||
        !config->response_policy_id_is_valid(bundle.response_policy_id) ||
        !config->failure_policy_id_is_valid(bundle.failure_policy_id) ||
        !config->timeout_failure_policy_id_is_valid(bundle.timeout_failure_policy_id))
        return false;
    const auto& response = config->response_policies[bundle.response_policy_id - 1];
    const auto& failure = config->failure_policies[bundle.failure_policy_id - 1];
    const auto& timeout = config->failure_policies[bundle.timeout_failure_policy_id - 1];
    if (!response_policy_spec_valid(response) || !forward_failure_policy_spec_valid(failure) ||
        !forward_timeout_failure_policy_spec_valid(timeout) ||
        response.version != ResponsePolicyVersion::Http11 ||
        response.framing != ResponsePolicyFraming::ContentLength ||
        response.connection != ResponsePolicyConnection::Request ||
        response.head_mode != ResponsePolicyHeadMode::SuppressBody ||
        failure.version != ForwardFailurePolicyVersion::Http11 || failure.status_code != 502 ||
        failure.connection != ForwardFailurePolicyConnection::Request ||
        failure.head_mode != FailurePolicyHeadMode::SuppressBody ||
        timeout.version != ForwardFailurePolicyVersion::Http11 || timeout.status_code != 504 ||
        timeout.connection != ForwardFailurePolicyConnection::Request ||
        timeout.head_mode != FailurePolicyHeadMode::SuppressBody ||
        timeout.body.len != c.http1_prebuilt_body_len || !c.response_policy_suppress_body ||
        !c.failure_policy_suppress_body)
        return false;
    HttpResponseParser parser;
    ParsedResponse parsed;
    parser.reset();
    parsed.reset();
    if (parser.parse(c.response_header_buf.data(), c.response_header_buf.len(), &parsed) !=
            ParseStatus::Complete ||
        parser.header_end != c.http1_prebuilt_header_end || parsed.version != HttpVersion::Http11 ||
        parsed.status_code != 504 || parsed.reason.len != timeout.reason.len ||
        (timeout.reason.len != 0 &&
         __builtin_memcmp(parsed.reason.ptr, timeout.reason.ptr, timeout.reason.len) != 0) ||
        parsed.content_length_count != 1 || parsed.content_length != c.http1_prebuilt_body_len ||
        parsed.chunked || parsed.headers_truncated ||
        parser.header_end != c.response_header_buf.len())
        return false;
    u32 server_count = 0;
    u32 date_count = 0;
    u32 content_type_count = 0;
    u32 connection_count = 0;
    for (u32 i = 0; i < parsed.header_count; ++i) {
        const Header& header = parsed.headers[i];
        if (http_header_name_eq_ci(header.name.ptr, header.name.len, "server", 6)) {
            ++server_count;
            if (header.value.len != timeout.server.len ||
                (timeout.server.len != 0 &&
                 __builtin_memcmp(header.value.ptr, timeout.server.ptr, timeout.server.len) != 0))
                return false;
        } else if (http_header_name_eq_ci(header.name.ptr, header.name.len, "date", 4)) {
            ++date_count;
            if (!response_read_deadline_http_date_is_normalized(header.value)) return false;
        } else if (http_header_name_eq_ci(header.name.ptr, header.name.len, "content-type", 12)) {
            ++content_type_count;
            if (header.value.len != timeout.content_type.len ||
                (timeout.content_type.len != 0 &&
                 __builtin_memcmp(
                     header.value.ptr, timeout.content_type.ptr, timeout.content_type.len) != 0))
                return false;
        } else if (http_header_name_eq_ci(header.name.ptr, header.name.len, "connection", 10)) {
            ++connection_count;
            const char* expected = c.keep_alive && c.req_client_keep_alive ? "keep-alive" : "close";
            const u32 expected_len = c.keep_alive && c.req_client_keep_alive ? 10u : 5u;
            if (header.value.len != expected_len ||
                __builtin_memcmp(header.value.ptr, expected, expected_len) != 0)
                return false;
        }
    }
    if (parsed.header_count != 5 || server_count != 1 || date_count != 1 ||
        content_type_count != 1 || connection_count != 1)
        return false;
    if (copied_proof.route_index >= config->route_count ||
        copied_proof.upstream_id >= config->upstream_count)
        return false;
    const RouteEntry& route = config->routes[copied_proof.route_index];
    const UpstreamTarget& target = config->upstreams[copied_proof.upstream_id];
    RouteParam params[kMaxRouteParams]{};
    u32 param_count = 0;
    return copied_proof.handler_generation != 0 &&
           copied_proof.handler_generation == c.handler_gen && copied_proof.route_fn != nullptr &&
           copied_proof.upstream_id == c.upstream_idx && copied_proof.raw_header_end != 0 &&
           copied_proof.raw_content_length == 0 &&
           copied_proof.raw_total_length == copied_proof.raw_header_end &&
           copied_proof.rewritten_header_end == c.req_header_end &&
           copied_proof.rewritten_total_length == c.req_initial_send_len &&
           copied_proof.expected_upload_length == copied_proof.rewritten_total_length &&
           copied_proof.request_policy_id == static_cast<u16>(RequestPolicyId::Http11FixedStrip) &&
           (explicit_close || default_keep_alive) && route.action == RouteAction::JitHandler &&
           route.fn == copied_proof.route_fn &&
           route.method == c.http1_prebuilt_deadline_route_method && !route.needs_req_body &&
           route.rate_limit.count == 0 && route.throttle_down_bps == 0 && !route.ws_terminate &&
           forward_preflight_mode_can_own_runtime_deadline(route.forward_preflight_mode) &&
           route.preflight_forward_policy_bundle_id == bundle_id && target.addr_count == 1 &&
           target.addrs[0].sin_family == AF_INET && target.max_inflight == 0 &&
           config->match_canonical(c.req_path_canon,
                                   route_method_key(static_cast<LogHttpMethod>(c.req_method)),
                                   params,
                                   &param_count,
                                   kMaxRouteParams) == &route;
}

inline bool response_read_deadline_owner_is_stable(const Connection& c,
                                                   Connection::Callback expected_upstream_recv,
                                                   ResponseReadDeadlineOwnerPhase phase);
inline bool header_only_head_keep_alive_precise_candidate(const Connection& c) {
    const auto& proof = c.response_read_deadline_upload;
    return c.response_read_deadline_profile == ResponseReadDeadlineProfile::HeaderOnlyHead &&
           !proof.downstream_close && response_read_deadline_default_persistence_is_stable(c) &&
           (c.request_policy_id == static_cast<u16>(RequestPolicyId::Http11FixedStrip) ||
            proof.request_policy_id == static_cast<u16>(RequestPolicyId::Http11FixedStrip));
}
inline bool header_only_head_keep_alive_arm_is_stable(const Connection& c,
                                                      const ResponseReadDeadlineUploadProof& proof,
                                                      const RouteConfig* config,
                                                      u16 bundle_id,
                                                      ResponseReadDeadlineOwnerPhase phase,
                                                      Connection::Callback expected_upstream_recv);
inline bool bodyless_get_keep_alive_precise_arm_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& proof,
    const RouteConfig* config,
    u16 bundle_id,
    ResponseReadDeadlineOwnerPhase phase,
    Connection::Callback expected_upstream_recv);

inline bool response_read_timeout_header_only_head_live_proof_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& copied_proof,
    const RouteConfig* config,
    u16 bundle_id,
    Connection::Callback expected_upstream_recv) {
    const bool live_owner = copied_proof.downstream_close
                                ? header_only_head_explicit_close_arm_is_stable(
                                      c,
                                      copied_proof,
                                      config,
                                      bundle_id,
                                      ResponseReadDeadlineOwnerPhase::ActiveAfterCopy,
                                      expected_upstream_recv)
                                : header_only_head_keep_alive_arm_is_stable(
                                      c,
                                      copied_proof,
                                      config,
                                      bundle_id,
                                      ResponseReadDeadlineOwnerPhase::ActiveAfterCopy,
                                      expected_upstream_recv);
    return live_owner &&
           response_read_timeout_header_only_head_response_is_stable(
               c,
               copied_proof,
               config,
               bundle_id,
               c.response_read_deadline_generation,
               ResponseReadTimeoutHeaderOnlyHeadPhase::PreBegin) &&
           config->policy_bundles[bundle_id - 1].response_read_timeout_seconds ==
               c.response_read_deadline_seconds &&
           copied_proof.upload_episode == c.upstream_episode;
}

inline bool response_read_deadline_persistence_owner_is_stable(
    const Connection& c, const ResponseReadDeadlineUploadProof& proof) {
    if (proof.downstream_close)
        return complete_content_length_explicit_close_is_stable(c, proof) ||
               header_only_head_explicit_close_is_stable(c, proof);
    return response_read_deadline_default_persistence_is_stable(c);
}

inline bool complete_content_length_request_policy_owner_is_stable(
    const Connection& c, const ResponseReadDeadlineUploadProof& proof) {
    if (response_read_deadline_profile_is_fixed_upload(c.response_read_deadline_profile)) {
        const bool admitted =
            c.response_read_deadline_profile ==
                    ResponseReadDeadlineProfile::FixedContentLengthUploadHeaderOnlyHead
                ? fixed_upload_head_request_policy_is_admitted(c.request_policy_id)
                : c.request_policy_id == static_cast<u16>(RequestPolicyId::Http11FixedStrip);
        return admitted && proof.request_policy_id == c.request_policy_id;
    }
    if (c.response_read_deadline_buffering != ForwardResponseBufferingMode::CompleteContentLength)
        return true;
    return complete_content_length_request_policy_is_admitted(c.request_policy_id) &&
           proof.request_policy_id == c.request_policy_id;
}

inline bool response_read_deadline_fixed_upload_materialization_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& proof,
    ResponseReadDeadlineProfile profile,
    bool require_upload_complete,
    u16 bundle_id,
    u8 route_method,
    ForwardResponseBufferingMode buffering,
    bool allow_retired_episode = false) {
    const RouteConfig* cfg = c.request_config;
    if (cfg == nullptr || !cfg->policy_bundle_id_is_valid(bundle_id) ||
        cfg->policy_bundles[bundle_id - 1].response_buffering != buffering ||
        !response_read_deadline_fixed_upload_profile_method_admitted(
            profile, c.req_method, buffering) ||
        proof.handler_generation == 0 || proof.handler_generation != c.handler_gen ||
        proof.route_index >= cfg->route_count || proof.upstream_id >= cfg->upstream_count ||
        (profile == ResponseReadDeadlineProfile::FixedContentLengthUploadHeaderOnlyHead
             ? !fixed_upload_head_request_policy_is_admitted(c.request_policy_id)
             : c.request_policy_id != static_cast<u16>(RequestPolicyId::Http11FixedStrip)) ||
        proof.request_policy_id != c.request_policy_id || proof.route_fn == nullptr ||
        proof.raw_header_end == 0 || proof.raw_content_length == 0 ||
        proof.raw_total_length <= proof.raw_header_end ||
        proof.raw_content_length != proof.raw_total_length - proof.raw_header_end ||
        proof.rewritten_header_end == 0 ||
        proof.rewritten_total_length <= proof.rewritten_header_end ||
        proof.rewritten_total_length - proof.rewritten_header_end != proof.raw_content_length ||
        proof.expected_upload_length != proof.rewritten_total_length ||
        !valid_upstream_episode(proof.upload_episode) ||
        (proof.upload_episode != c.upstream_episode &&
         (!allow_retired_episode || proof.upload_episode != c.upstream_retiring_episode)))
        return false;
    const RouteEntry& route = cfg->routes[proof.route_index];
    const UpstreamTarget& target = cfg->upstreams[proof.upstream_id];
    return route.action == RouteAction::JitHandler && route.fn == proof.route_fn &&
           route.fn != nullptr && !route.needs_req_body && route.rate_limit.count == 0 &&
           route.throttle_down_bps == 0 && !route.ws_terminate &&
           forward_preflight_mode_can_own_runtime_deadline(route.forward_preflight_mode) &&
           route.preflight_forward_policy_bundle_id == bundle_id && route.method == route_method &&
           response_read_deadline_route_method_matches(c.req_method, route.method) &&
           target.addr_count == 1 && target.addrs[0].sin_family == AF_INET &&
           target.max_inflight == 0 && c.upstream_idx == proof.upstream_id &&
           c.request_policy_id == proof.request_policy_id && c.req_client_has_content_length &&
           c.req_content_length == proof.raw_content_length &&
           c.req_body_mode == BodyMode::ContentLength && c.req_body_remaining == 0 &&
           c.request_body_fully_buffered && !c.request_policy_body_pending &&
           !c.req_body_streamed && c.req_header_end == proof.rewritten_header_end &&
           c.req_initial_send_len == proof.rewritten_total_length &&
           (!require_upload_complete || c.request_upload_complete) &&
           !c.upstream_request_incomplete;
}

inline bool response_read_deadline_fixed_upload_materialization_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& proof,
    bool require_upload_complete) {
    return response_read_deadline_fixed_upload_materialization_is_stable(
        c,
        proof,
        c.response_read_deadline_profile,
        require_upload_complete,
        c.response_read_deadline_bundle_id,
        c.response_read_deadline_route_method,
        c.response_read_deadline_buffering);
}

inline bool response_read_deadline_fixed_upload_proof_is_stable(
    const Connection& c, const ResponseReadDeadlineUploadProof& proof) {
    return response_read_deadline_fixed_upload_materialization_is_stable(
        c, proof, /*require_upload_complete=*/true);
}

// The staged fixed-upload HEAD success path is deliberately narrower than the
// generic fixed-upload and bodyless HEAD owners.  It may be checked while the
// origin recv is live or after that exact episode has moved into the strict
// retirement tombstone, but never creates or selects the profile itself.
inline bool fixed_upload_head_success_proof_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& proof,
    const RouteConfig* config,
    u16 bundle_id,
    ResponseReadDeadlineProfile profile,
    ForwardResponseBufferingMode buffering,
    u8 method,
    u8 route_method,
    bool allow_retired_episode = false,
    bool allow_consumed_terminal_episode = false) {
    if (config == nullptr || config != c.request_config ||
        !config->policy_bundle_id_is_valid(bundle_id) ||
        profile != ResponseReadDeadlineProfile::FixedContentLengthUploadHeaderOnlyHead ||
        buffering != ForwardResponseBufferingMode::None ||
        method != static_cast<u8>(LogHttpMethod::Head) || method != c.req_method ||
        !response_read_deadline_route_method_matches(method, route_method) ||
        c.pipeline_depth != 0 || c.http1_pipeline_request_generation != 0 ||
        c.protocol != ConnProtocol::Http11 || c.tls_active || c.h2 != nullptr ||
        c.req_http_version != static_cast<u8>(HttpVersion::Http11) || !c.req_strict_h1_complete ||
        c.req_path_canon.ptr == nullptr || c.req_client_content_length_count != 1 ||
        !c.req_client_has_content_length || c.req_client_has_transfer_encoding ||
        c.req_client_has_te || c.req_client_has_expect || c.req_client_has_upgrade_header ||
        c.req_malformed || c.req_wants_upgrade || c.req_upgrade_is_websocket ||
        c.resp_upgrade_is_websocket || !response_read_deadline_default_persistence_is_stable(c) ||
        proof.downstream_close || !c.response_policy_suppress_body ||
        !c.failure_policy_suppress_body || c.response_mutations_snapshotted ||
        c.target_transform_recorded || c.req_path_overridden || c.req_header_override_count != 0 ||
        c.req_header_override_overflow || c.resp_header_mutation_count != 0 ||
        c.resp_header_mutation_pending_count != 0 || c.resp_header_mutation_pending_overflow ||
        c.resp_header_mutation_overflow || c.upstream_reused || c.upstream_attempts != 1 ||
        !c.request_upload_complete || c.upstream_request_incomplete || c.retry_req_send_len != 0 ||
        c.pipeline_stash_len != 0 ||
        !response_read_deadline_fixed_upload_materialization_is_stable(
            c, proof, profile, true, bundle_id, route_method, buffering, allow_retired_episode))
        return false;
    const auto& bundle = config->policy_bundles[bundle_id - 1];
    if (bundle.response_buffering != buffering ||
        bundle.response_policy_id != c.response_policy_id ||
        bundle.failure_policy_id != c.failure_policy_id ||
        bundle.timeout_failure_policy_id != c.timeout_failure_policy_id ||
        !response_read_timeout_seconds_valid(bundle.response_read_timeout_seconds) ||
        !config->response_policy_id_is_valid(bundle.response_policy_id) ||
        !config->failure_policy_id_is_valid(bundle.failure_policy_id) ||
        !config->timeout_failure_policy_id_is_valid(bundle.timeout_failure_policy_id))
        return false;
    const auto& response = config->response_policies[bundle.response_policy_id - 1];
    const auto& failure = config->failure_policies[bundle.failure_policy_id - 1];
    const auto& timeout = config->failure_policies[bundle.timeout_failure_policy_id - 1];
    if (!response_policy_spec_valid(response) || !forward_failure_policy_spec_valid(failure) ||
        !forward_timeout_failure_policy_spec_valid(timeout) ||
        response.version != ResponsePolicyVersion::Http11 ||
        response.framing != ResponsePolicyFraming::ContentLength ||
        response.connection != ResponsePolicyConnection::Request ||
        response.head_mode != ResponsePolicyHeadMode::SuppressBody ||
        failure.version != ForwardFailurePolicyVersion::Http11 || failure.status_code != 502 ||
        failure.connection != ForwardFailurePolicyConnection::Request ||
        failure.head_mode != FailurePolicyHeadMode::SuppressBody ||
        timeout.version != ForwardFailurePolicyVersion::Http11 ||
        timeout.connection != ForwardFailurePolicyConnection::Request ||
        timeout.head_mode != FailurePolicyHeadMode::SuppressBody)
        return false;
    const bool live =
        proof.upload_episode == c.upstream_episode && c.upstream_fd >= 0 && !c.upstream_abandoned &&
        !c.upstream_retirement_active && c.upstream_retirement_target_owned == 0 &&
        c.upstream_retirement_cancel_owned == 0 && c.upstream_retirement_cancel_retry == 0 &&
        c.upstream_recv_armed && c.on_upstream_recv != nullptr;
    const bool retired = allow_retired_episode && c.upstream_abandoned && c.upstream_fd < 0 &&
                         proof.upload_episode == c.upstream_retiring_episode &&
                         valid_upstream_episode(c.upstream_retiring_episode) &&
                         valid_upstream_episode(c.upstream_episode) &&
                         c.upstream_retiring_episode < c.upstream_episode &&
                         c.on_upstream_recv == nullptr && c.on_upstream_send == nullptr;
    // The io_uring dispatcher accounts a positive terminal Recv before invoking
    // its callback.  A caller may admit that owner-free instant only when it has
    // independently retained the exact current-batch CQE witness; this predicate
    // still proves all persistent request/policy/transport state and deliberately
    // does not infer terminal ownership from !upstream_recv_armed alone.
    const bool consumed_terminal =
        allow_consumed_terminal_episode && proof.upload_episode == c.upstream_episode &&
        c.upstream_fd >= 0 && !c.upstream_abandoned && !c.upstream_retirement_active &&
        c.upstream_retirement_target_owned == 0 && c.upstream_retirement_cancel_owned == 0 &&
        c.upstream_retirement_cancel_retry == 0 && !c.upstream_recv_armed &&
        c.on_upstream_recv != nullptr && c.on_upstream_send == nullptr;
    return live || retired || consumed_terminal;
}

// First-batch and D2 callers retain the immutable bundle/route identity after
// the live deadline latch may have moved phases. They prove CompleteContentLength
// at their boundary and use this helper for the exact policy/upload episode.
inline bool complete_content_length_fixed_upload_materialization_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& proof,
    ResponseReadDeadlineProfile profile,
    bool require_upload_complete,
    u16 bundle_id,
    u8 route_method,
    ForwardResponseBufferingMode buffering,
    bool retired_episode = false) {
    if (profile != ResponseReadDeadlineProfile::FixedContentLengthUploadNonHeadContentLengthZero ||
        buffering != ForwardResponseBufferingMode::CompleteContentLength ||
        c.request_policy_id != static_cast<u16>(RequestPolicyId::Http11FixedStrip) ||
        proof.request_policy_id != c.request_policy_id ||
        !complete_content_length_route_method_is_admitted(route_method) ||
        !response_read_deadline_route_method_matches(c.req_method, route_method) ||
        !response_read_deadline_fixed_upload_materialization_is_stable(c,
                                                                       proof,
                                                                       profile,
                                                                       require_upload_complete,
                                                                       bundle_id,
                                                                       route_method,
                                                                       buffering,
                                                                       retired_episode))
        return false;
    return retired_episode ? proof.upload_episode == c.upstream_retiring_episode
                           : proof.upload_episode == c.upstream_episode;
}

inline bool complete_content_length_fixed_upload_composition_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& proof,
    bool require_upload_complete,
    u16 bundle_id,
    u8 route_method,
    bool retired_episode = false) {
    return c.response_read_deadline_buffering ==
               ForwardResponseBufferingMode::CompleteContentLength &&
           response_read_deadline_profile_is_fixed_upload(c.response_read_deadline_profile) &&
           complete_content_length_fixed_upload_materialization_is_stable(
               c,
               proof,
               c.response_read_deadline_profile,
               require_upload_complete,
               bundle_id,
               route_method,
               c.response_read_deadline_buffering,
               retired_episode);
}

inline bool complete_content_length_fixed_upload_composition_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& proof,
    bool require_upload_complete,
    bool retired_episode = false) {
    return complete_content_length_fixed_upload_composition_is_stable(
        c,
        proof,
        require_upload_complete,
        c.response_read_deadline_bundle_id,
        c.response_read_deadline_route_method,
        retired_episode);
}

inline bool response_read_deadline_route_method_matches(u8 method, u8 route_method) {
    const auto parsed = static_cast<LogHttpMethod>(method);
    const u8 exact = route_method_key(parsed);
    if (exact == kRouteMethodInvalid || exact == kRouteMethodAny) return false;
    // TRACE has no explicit route syntax. It is intentionally admitted only
    // through a method-omitted route, even if a forged RouteEntry contains the
    // otherwise representable internal TRACE key.
    if (parsed == LogHttpMethod::Trace) return route_method == kRouteMethodAny;
    return route_method == kRouteMethodAny || route_method == exact;
}

// A request-policy-materialized bodyless GET reuses the fixed-upload proof as
// immutable request identity. Coalesced layouts additionally validate the
// preserved successor stash; exact layouts keep it empty. A legacy ID0 owner
// leaves these fields neutral, so it cannot enter this proof domain.
inline bool response_read_deadline_coalesced_get_phase1_proof_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& proof,
    bool allow_retired_episode = false,
    bool require_upload_episode = true,
    ResponseReadDeadlineProfile identity_profile = ResponseReadDeadlineProfile::None,
    ForwardResponseBufferingMode identity_buffering = ForwardResponseBufferingMode::None,
    u16 identity_bundle_id = 0,
    u8 identity_method = 0xffu,
    u8 identity_route_method = 0xffu) {
    const RouteConfig* cfg = c.request_config;
    if (identity_profile == ResponseReadDeadlineProfile::None)
        identity_profile = c.response_read_deadline_profile;
    if (identity_buffering == ForwardResponseBufferingMode::None)
        identity_buffering = c.response_read_deadline_buffering;
    if (identity_bundle_id == 0) identity_bundle_id = c.response_read_deadline_bundle_id;
    if (identity_method == 0xffu) identity_method = c.response_read_deadline_method;
    if (identity_route_method == 0xffu)
        identity_route_method = c.response_read_deadline_route_method;
    if (cfg == nullptr ||
        identity_profile != ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero ||
        identity_buffering != ForwardResponseBufferingMode::CompleteContentLength ||
        c.req_method != static_cast<u8>(LogHttpMethod::Get) ||
        identity_method != static_cast<u8>(LogHttpMethod::Get) ||
        identity_route_method != kRouteMethodGet ||
        c.request_policy_id != static_cast<u16>(RequestPolicyId::Http11FixedStrip) ||
        proof.request_policy_id != c.request_policy_id || proof.handler_generation == 0 ||
        proof.handler_generation != c.handler_gen || proof.route_index >= cfg->route_count ||
        proof.route_fn == nullptr || proof.raw_header_end == 0 || proof.raw_content_length != 0 ||
        proof.raw_total_length != proof.raw_header_end || proof.rewritten_header_end == 0 ||
        proof.rewritten_total_length != proof.rewritten_header_end ||
        proof.expected_upload_length != proof.rewritten_total_length ||
        proof.upstream_id >= cfg->upstream_count || proof.upstream_id != c.upstream_idx ||
        (require_upload_episode ? !valid_upstream_episode(proof.upload_episode)
                                : proof.upload_episode != 0) ||
        proof.downstream_close)
        return false;
    const RouteEntry& route = cfg->routes[proof.route_index];
    const UpstreamTarget& target = cfg->upstreams[proof.upstream_id];
    const bool episode =
        !require_upload_episode || proof.upload_episode == c.upstream_episode ||
        (allow_retired_episode && proof.upload_episode == c.upstream_retiring_episode);
    return episode && route.action == RouteAction::JitHandler && route.fn == proof.route_fn &&
           !route.needs_req_body && route.rate_limit.count == 0 && route.throttle_down_bps == 0 &&
           !route.ws_terminate &&
           forward_preflight_mode_can_own_runtime_deadline(route.forward_preflight_mode) &&
           route.preflight_forward_policy_bundle_id == identity_bundle_id &&
           route.method == kRouteMethodGet && target.addr_count == 1 &&
           target.addrs[0].sin_family == AF_INET && target.max_inflight == 0 &&
           c.req_header_end == proof.rewritten_header_end &&
           c.req_initial_send_len == proof.rewritten_total_length &&
           c.req_body_mode == BodyMode::None && c.req_body_remaining == 0 &&
           !c.request_body_fully_buffered && !c.req_body_streamed &&
           !c.req_client_has_content_length && !c.req_client_has_transfer_encoding &&
           !c.req_client_has_te && !c.req_client_has_expect && !c.req_client_has_upgrade_header &&
           !c.req_malformed && !c.req_wants_upgrade && c.pipeline_depth == 0 &&
           c.retry_req_send_len == 0 && !c.response_mutations_snapshotted &&
           !c.target_transform_recorded && !c.req_path_overridden &&
           c.req_header_override_count == 0 && !c.req_header_override_overflow &&
           c.resp_header_mutation_count == 0 && c.resp_header_mutation_pending_count == 0 &&
           !c.resp_header_mutation_pending_overflow && !c.resp_header_mutation_overflow &&
           !c.upstream_reused && c.upstream_attempts == 1;
}

inline bool response_read_deadline_coalesced_get_phase1_prebuilt_stash_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& proof,
    ResponseReadDeadlineProfile profile,
    ForwardResponseBufferingMode buffering,
    u16 bundle_id,
    u8 method,
    u8 route_method,
    bool allow_retired_episode = true) {
    return response_read_deadline_coalesced_get_phase1_proof_is_stable(
               c,
               proof,
               allow_retired_episode,
               /*require_upload_episode=*/true,
               profile,
               buffering,
               bundle_id,
               method,
               route_method) &&
           c.pipeline_stash_len != 0 && c.send_buf.len() == c.pipeline_stash_len &&
           c.recv_buf.len() <= c.recv_buf.capacity() - c.pipeline_stash_len;
}

inline bool response_read_deadline_coalesced_get_phase1_stash_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& proof,
    bool allow_retired_episode = false) {
    if (!response_read_deadline_coalesced_get_phase1_proof_is_stable(
            c, proof, allow_retired_episode) ||
        c.pipeline_stash_len == 0 || c.send_buf.len() != c.pipeline_stash_len ||
        c.recv_buf.len() > c.recv_buf.capacity() - c.pipeline_stash_len)
        return false;
    return true;
}

// #278 staged identity contract for a completely admitted depth-1 HTTP/1
// successor.  Every predicate is pure and preserves the depth-0/token-0 legacy
// branch without re-checking its method, upload, policy, or response profile;
// the enclosing legacy guards remain authoritative for that branch.
inline bool http1_pipeline_request_is_legacy(const Connection& c) {
    return c.pipeline_depth == 0 && c.http1_pipeline_request_generation == 0;
}

inline bool http1_pipeline_request_is_current_successor(const Connection& c) {
    return c.pipeline_depth == 1 && c.handler_gen != 0 &&
           c.http1_pipeline_request_generation == c.handler_gen;
}

inline bool http1_pipeline_successor_tombstone_is_safe(const Connection& c) {
    return c.upstream_retiring_episode == 0 ||
           (valid_upstream_episode(c.upstream_retiring_episode) &&
            c.upstream_retiring_episode < c.upstream_episode);
}

inline bool http1_pipeline_successor_upstream_owners_are_neutral(const Connection& c) {
    return c.upstream_fd < 0 && !c.upstream_reused && !c.upstream_slot_held &&
           c.on_upstream_recv == nullptr && c.on_upstream_send == nullptr &&
           !c.upstream_connect_armed && !c.upstream_send_armed && !c.upstream_recv_armed &&
           !c.upstream_recv_paused_for_send && !c.upstream_recv_pause_cancel_pending &&
           !c.upstream_recv_pause_rearm_pending && !c.upstream_recv_cancel_inflight &&
           !c.upstream_retirement_active && c.upstream_retirement_target_owned == 0 &&
           c.upstream_retirement_cancel_owned == 0 && c.upstream_retirement_cancel_retry == 0 &&
           c.upstream_close_episode == 0 && c.upstream_close_target_owned == 0 &&
           c.upstream_close_cancel_owned == 0 && !c.upstream_close_pause_cancel_owned &&
           c.idle_return_fd < 0 && c.idle_return_config == nullptr && !c.close_after_idle_return &&
           c.upstream_recv_buf.len() == 0 && !c.h2_proxy_recv_draining &&
           !c.h2_proxy_synth_quarantined;
}

inline bool http1_pipeline_successor_semantic_shape_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& proof,
    ResponseReadDeadlineProfile profile,
    ForwardResponseBufferingMode buffering,
    u8 method,
    u8 route_method) {
    return profile == ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero &&
           buffering == ForwardResponseBufferingMode::CompleteContentLength &&
           method == static_cast<u8>(LogHttpMethod::Get) && route_method == kRouteMethodGet &&
           c.protocol == ConnProtocol::Http11 && !c.tls_active && c.h2 == nullptr &&
           c.req_http_version == static_cast<u8>(HttpVersion::Http11) && c.req_strict_h1_complete &&
           c.req_method == method && c.req_path_canon.ptr != nullptr &&
           response_read_deadline_route_method_matches(c.req_method, route_method) &&
           (proof.downstream_close ? complete_content_length_explicit_close_request_is_stable(
                                         c, proof, buffering, profile)
                                   : response_read_deadline_default_persistence_is_stable(c)) &&
           !c.req_client_has_content_length && !c.req_client_has_transfer_encoding &&
           !c.req_client_has_te && !c.req_client_has_expect && !c.req_client_has_upgrade_header &&
           c.req_body_mode == BodyMode::None && c.req_body_remaining == 0 &&
           !c.request_body_fully_buffered && !c.req_body_streamed && !c.req_malformed &&
           !c.req_wants_upgrade && !c.req_upgrade_is_websocket && !c.resp_upgrade_is_websocket &&
           c.req_header_end != 0 && c.req_initial_send_len == c.req_header_end &&
           c.pipeline_stash_len == 0 && c.retry_req_send_len == 0 &&
           !c.response_mutations_snapshotted && !c.target_transform_recorded &&
           !c.req_path_overridden && c.req_header_override_count == 0 &&
           !c.req_header_override_overflow && c.resp_header_mutation_count == 0 &&
           c.resp_header_mutation_pending_count == 0 && !c.resp_header_mutation_pending_overflow &&
           !c.resp_header_mutation_overflow;
}

inline bool http1_pipeline_successor_request_shape_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& proof,
    ResponseReadDeadlineProfile profile,
    ForwardResponseBufferingMode buffering,
    u8 method,
    u8 route_method) {
    return http1_pipeline_successor_semantic_shape_is_stable(
               c, proof, profile, buffering, method, route_method) &&
           c.recv_buf.len() == c.req_initial_send_len;
}

inline bool http1_pipeline_request_generation_provisional_is_stable(
    const Connection& c,
    ResponseReadDeadlineProfile candidate_profile,
    ForwardResponseBufferingMode candidate_buffering,
    u8 candidate_method,
    u8 candidate_route_method,
    bool candidate_downstream_close = false) {
    if (http1_pipeline_request_is_legacy(c)) return true;
    ResponseReadDeadlineUploadProof candidate_proof{};
    candidate_proof.downstream_close = candidate_downstream_close;
    if (!http1_pipeline_request_is_current_successor(c) ||
        !http1_pipeline_successor_request_shape_is_stable(c,
                                                          candidate_proof,
                                                          candidate_profile,
                                                          candidate_buffering,
                                                          candidate_method,
                                                          candidate_route_method) ||
        c.upstream_attempts > 1 || !valid_upstream_episode(c.upstream_episode) ||
        c.upstream_episode_quarantined || !http1_pipeline_successor_tombstone_is_safe(c) ||
        !http1_pipeline_successor_upstream_owners_are_neutral(c))
        return false;
    return true;
}

inline bool http1_pipeline_request_generation_jit_candidate_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& preflight_proof,
    ResponseReadDeadlineProfile candidate_profile,
    ForwardResponseBufferingMode candidate_buffering,
    u8 candidate_method,
    u8 candidate_route_method,
    u16 candidate_request_policy_id) {
    if (http1_pipeline_request_is_legacy(c)) return true;
    return http1_pipeline_request_generation_provisional_is_stable(
               c,
               candidate_profile,
               candidate_buffering,
               candidate_method,
               candidate_route_method,
               preflight_proof.downstream_close) &&
           candidate_request_policy_id == static_cast<u16>(RequestPolicyId::Http11FixedStrip) &&
           c.request_policy_id == 0 &&
           response_read_deadline_upload_proof_equal(c.response_read_deadline_upload,
                                                     preflight_proof) &&
           preflight_proof.handler_generation == c.handler_gen &&
           preflight_proof.handler_generation == c.http1_pipeline_request_generation &&
           preflight_proof.raw_header_end == 0 && preflight_proof.raw_content_length == 0 &&
           preflight_proof.raw_total_length == 0 && preflight_proof.rewritten_header_end == 0 &&
           preflight_proof.rewritten_total_length == 0 && preflight_proof.upload_episode == 0 &&
           preflight_proof.expected_upload_length == 0 && preflight_proof.route_index == 0xffffu &&
           preflight_proof.upstream_id == 0xffffu && preflight_proof.request_policy_id == 0 &&
           preflight_proof.route_fn == nullptr;
}

inline bool http1_pipeline_successor_selected_identity_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& proof,
    ResponseReadDeadlineProfile profile,
    ForwardResponseBufferingMode buffering,
    u8 method,
    u8 route_method,
    bool require_materialized_request) {
    const RouteConfig* cfg = c.request_config;
    if (!http1_pipeline_request_is_current_successor(c) || cfg == nullptr ||
        !(require_materialized_request ? http1_pipeline_successor_request_shape_is_stable(
                                             c, proof, profile, buffering, method, route_method)
                                       : http1_pipeline_successor_semantic_shape_is_stable(
                                             c, proof, profile, buffering, method, route_method)) ||
        c.response_read_deadline_profile != profile ||
        c.response_read_deadline_buffering != buffering ||
        c.response_read_deadline_method != method ||
        c.response_read_deadline_route_method != route_method ||
        c.request_policy_id != static_cast<u16>(RequestPolicyId::Http11FixedStrip) ||
        proof.request_policy_id != c.request_policy_id ||
        proof.handler_generation != c.handler_gen ||
        proof.handler_generation != c.http1_pipeline_request_generation ||
        proof.route_index >= cfg->route_count || proof.route_fn == nullptr ||
        proof.upstream_id >= cfg->upstream_count || proof.upstream_id != c.upstream_idx ||
        c.upstream_attempts != 1 || !valid_upstream_episode(c.upstream_episode) ||
        c.upstream_episode_quarantined || !http1_pipeline_successor_tombstone_is_safe(c) ||
        !response_read_deadline_upload_proof_equal(c.response_read_deadline_upload, proof))
        return false;
    const RouteEntry& route = cfg->routes[proof.route_index];
    const UpstreamTarget& target = cfg->upstreams[proof.upstream_id];
    return route.action == RouteAction::JitHandler && route.fn == proof.route_fn &&
           !route.needs_req_body && route.rate_limit.count == 0 && route.throttle_down_bps == 0 &&
           !route.ws_terminate && route.method == kRouteMethodGet &&
           cfg->policy_bundle_id_is_valid(c.response_read_deadline_bundle_id) &&
           forward_preflight_mode_can_own_runtime_deadline(route.forward_preflight_mode) &&
           route.preflight_forward_policy_bundle_id == c.response_read_deadline_bundle_id &&
           target.addr_count == 1 && target.addrs[0].sin_family == AF_INET &&
           target.max_inflight == 0;
}

inline bool http1_pipeline_request_generation_preconnect_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& proof,
    ResponseReadDeadlineProfile profile,
    ForwardResponseBufferingMode buffering,
    u8 method,
    u8 route_method) {
    if (http1_pipeline_request_is_legacy(c)) return true;
    return http1_pipeline_successor_selected_identity_is_stable(
               c, proof, profile, buffering, method, route_method, true) &&
           proof.raw_header_end == 0 && proof.raw_content_length == 0 &&
           proof.raw_total_length == 0 && proof.rewritten_header_end == c.req_header_end &&
           proof.rewritten_total_length == c.req_initial_send_len &&
           proof.expected_upload_length == proof.rewritten_total_length &&
           proof.upload_episode == 0;
}

inline bool http1_pipeline_request_generation_upload_active_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& proof,
    ResponseReadDeadlineProfile profile,
    ForwardResponseBufferingMode buffering,
    u8 method,
    u8 route_method,
    bool allow_retired_episode = false) {
    if (http1_pipeline_request_is_legacy(c)) return true;
    const bool episode =
        proof.upload_episode == c.upstream_episode ||
        (allow_retired_episode && proof.upload_episode == c.upstream_retiring_episode);
    return http1_pipeline_successor_selected_identity_is_stable(
               c, proof, profile, buffering, method, route_method, false) &&
           proof.raw_header_end == 0 && proof.raw_content_length == 0 &&
           proof.raw_total_length == 0 && proof.rewritten_header_end == c.req_header_end &&
           proof.rewritten_total_length == c.req_initial_send_len &&
           proof.expected_upload_length == proof.rewritten_total_length &&
           valid_upstream_episode(proof.upload_episode) && episode;
}

template <typename Loop>
inline bool http1_pipeline_request_generation_connected_is_stable(
    const Loop* loop,
    const Connection& c,
    const IoEvent& ev,
    Connection::Callback expected_upstream_connect) {
    if (http1_pipeline_request_is_legacy(c)) return true;
    if constexpr (!requires(const Loop* candidate) {
                      candidate->backend.send_state[0];
                      candidate->backend.upstream_send_state[0];
                      candidate->conns[0];
                  }) {
        return false;
    } else {
        if (loop == nullptr || expected_upstream_connect == nullptr || c.id >= Loop::kMaxConns ||
            &loop->conns[c.id] != &c || c.fd < 0 || c.req_start_us == 0 ||
            c.state != ConnState::Proxying || c.upstream_fd < 0 ||
            c.on_upstream_send != expected_upstream_connect || c.on_upstream_recv != nullptr ||
            c.on_recv != nullptr || c.on_send != nullptr || c.upstream_connect_armed ||
            c.upstream_send_armed || c.upstream_recv_armed || c.upstream_slot_held ||
            c.upstream_retirement_active || c.upstream_retirement_target_owned != 0 ||
            c.upstream_retirement_cancel_owned != 0 || c.upstream_retirement_cancel_retry != 0 ||
            c.upstream_close_episode != 0 || c.upstream_close_target_owned != 0 ||
            c.upstream_close_cancel_owned != 0 || c.upstream_close_pause_cancel_owned ||
            c.idle_return_fd >= 0 || c.idle_return_config != nullptr || c.close_after_idle_return ||
            loop->backend.send_state[c.id].remaining != 0 ||
            loop->backend.upstream_send_state[c.id].remaining != 0 ||
            ev.type != IoEventType::UpstreamConnect || ev.result != 0 || ev.aux != 0 || ev.more ||
            ev.conn_id != c.id || ev.upstream_episode != c.upstream_episode ||
            !http1_pipeline_request_generation_preconnect_is_stable(
                c,
                c.response_read_deadline_upload,
                c.response_read_deadline_profile,
                c.response_read_deadline_buffering,
                c.response_read_deadline_method,
                c.response_read_deadline_route_method))
            return false;
        const bool live_downstream_recv = c.recv_armed && c.pending_ops == 1u;
        const bool terminal_downstream_recv_consumed = !c.recv_armed && c.pending_ops == 0u;
        return live_downstream_recv || terminal_downstream_recv_consumed;
    }
}

inline bool http1_pipeline_request_generation_prebuilt_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& copied_proof,
    const RouteConfig* copied_config,
    u16 copied_bundle_id,
    ResponseReadDeadlineProfile copied_profile,
    ForwardResponseBufferingMode copied_buffering,
    u8 copied_method,
    u8 copied_route_method,
    Http1PrebuiltResponseLayout copied_layout,
    Http1PrebuiltResponsePurpose copied_purpose) {
    if (http1_pipeline_request_is_legacy(c)) return true;
    if (!http1_pipeline_request_is_current_successor(c) || copied_config == nullptr ||
        copied_config != c.request_config ||
        !copied_config->policy_bundle_id_is_valid(copied_bundle_id) ||
        !http1_pipeline_successor_semantic_shape_is_stable(c,
                                                           copied_proof,
                                                           copied_profile,
                                                           copied_buffering,
                                                           copied_method,
                                                           copied_route_method) ||
        copied_profile != ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero ||
        copied_buffering != ForwardResponseBufferingMode::CompleteContentLength ||
        copied_method != static_cast<u8>(LogHttpMethod::Get) ||
        copied_route_method != kRouteMethodGet ||
        copied_layout != Http1PrebuiltResponseLayout::FullContentLengthNonHead ||
        (copied_purpose != Http1PrebuiltResponsePurpose::StrictNonHeadCl0Success &&
         copied_purpose != Http1PrebuiltResponsePurpose::ResponseReadTimeout) ||
        c.http1_prebuilt_deadline_config != copied_config ||
        c.http1_prebuilt_deadline_bundle_id != copied_bundle_id ||
        c.http1_prebuilt_deadline_profile != copied_profile ||
        c.http1_prebuilt_deadline_method != copied_method ||
        c.http1_prebuilt_deadline_route_method != copied_route_method ||
        c.http1_prebuilt_response_layout != copied_layout ||
        c.http1_prebuilt_response_purpose != copied_purpose ||
        !response_read_deadline_upload_proof_equal(c.http1_prebuilt_deadline_upload,
                                                   copied_proof) ||
        copied_proof.handler_generation != c.handler_gen ||
        copied_proof.handler_generation != c.http1_pipeline_request_generation ||
        copied_proof.route_index >= copied_config->route_count ||
        copied_proof.route_fn == nullptr || copied_proof.raw_header_end != 0 ||
        copied_proof.raw_content_length != 0 || copied_proof.raw_total_length != 0 ||
        copied_proof.rewritten_header_end != c.req_header_end ||
        copied_proof.rewritten_total_length != c.req_initial_send_len ||
        copied_proof.rewritten_total_length != copied_proof.rewritten_header_end ||
        copied_proof.expected_upload_length != copied_proof.rewritten_total_length ||
        copied_proof.request_policy_id != static_cast<u16>(RequestPolicyId::Http11FixedStrip) ||
        copied_proof.request_policy_id != c.request_policy_id ||
        copied_proof.upstream_id >= copied_config->upstream_count ||
        copied_proof.upstream_id != c.upstream_idx || c.http1_prebuilt_deadline_generation == 0 ||
        c.http1_prebuilt_deadline_generation != c.response_read_deadline_generation ||
        !valid_upstream_episode(copied_proof.upload_episode) ||
        (copied_proof.upload_episode != c.upstream_episode &&
         copied_proof.upload_episode != c.upstream_retiring_episode) ||
        !valid_upstream_episode(c.upstream_episode) || c.upstream_episode_quarantined ||
        !http1_pipeline_successor_tombstone_is_safe(c))
        return false;
    const auto& bundle = copied_config->policy_bundles[copied_bundle_id - 1];
    const RouteEntry& route = copied_config->routes[copied_proof.route_index];
    const UpstreamTarget& target = copied_config->upstreams[copied_proof.upstream_id];
    return bundle.response_buffering == copied_buffering &&
           route.action == RouteAction::JitHandler && route.fn == copied_proof.route_fn &&
           route.method == kRouteMethodGet &&
           forward_preflight_mode_can_own_runtime_deadline(route.forward_preflight_mode) &&
           route.preflight_forward_policy_bundle_id == copied_bundle_id && !route.needs_req_body &&
           route.rate_limit.count == 0 && route.throttle_down_bps == 0 && !route.ws_terminate &&
           target.addr_count == 1 && target.addrs[0].sin_family == AF_INET &&
           target.max_inflight == 0;
}

inline bool response_read_deadline_owner_is_stable(const Connection& c,
                                                   Connection::Callback expected_upstream_recv,
                                                   ResponseReadDeadlineOwnerPhase phase) {
    const RouteConfig* cfg = c.request_config;
    const u16 bundle_id = c.response_read_deadline_bundle_id;
    if (cfg == nullptr || c.response_read_deadline_profile == ResponseReadDeadlineProfile::None ||
        c.response_read_deadline_owner_generation == 0 ||
        c.response_read_deadline_owner_generation != c.response_read_deadline_generation ||
        !cfg->policy_bundle_id_is_valid(bundle_id))
        return false;
    if (c.response_read_deadline_method != c.req_method ||
        !response_read_deadline_route_method_matches(c.response_read_deadline_method,
                                                     c.response_read_deadline_route_method))
        return false;
    const auto& bundle = cfg->policy_bundles[bundle_id - 1];
    if (!response_read_timeout_seconds_valid(bundle.response_read_timeout_seconds) ||
        bundle.response_read_timeout_seconds != c.response_read_deadline_seconds ||
        bundle.response_buffering != c.response_read_deadline_buffering ||
        bundle.response_policy_id != c.response_policy_id ||
        bundle.failure_policy_id != c.failure_policy_id ||
        bundle.timeout_failure_policy_id != c.timeout_failure_policy_id ||
        !cfg->response_policy_id_is_valid(bundle.response_policy_id) ||
        !cfg->failure_policy_id_is_valid(bundle.failure_policy_id) ||
        !cfg->timeout_failure_policy_id_is_valid(bundle.timeout_failure_policy_id))
        return false;
    if (!complete_content_length_request_policy_owner_is_stable(c, c.response_read_deadline_upload))
        return false;
    const auto& response = cfg->response_policies[bundle.response_policy_id - 1];
    const auto& failure = cfg->failure_policies[bundle.failure_policy_id - 1];
    const auto& timeout = cfg->failure_policies[bundle.timeout_failure_policy_id - 1];
    if (!response_policy_spec_valid(response) || !forward_failure_policy_spec_valid(failure) ||
        !forward_timeout_failure_policy_spec_valid(timeout) ||
        response.version != ResponsePolicyVersion::Http11 ||
        response.framing != ResponsePolicyFraming::ContentLength ||
        response.connection != ResponsePolicyConnection::Request ||
        failure.version != ForwardFailurePolicyVersion::Http11 || failure.status_code != 502 ||
        failure.connection != ForwardFailurePolicyConnection::Request ||
        timeout.version != ForwardFailurePolicyVersion::Http11 ||
        timeout.connection != ForwardFailurePolicyConnection::Request)
        return false;
    const bool pipeline_generation_stable =
        http1_pipeline_request_generation_upload_active_is_stable(
            c,
            c.response_read_deadline_upload,
            c.response_read_deadline_profile,
            c.response_read_deadline_buffering,
            c.response_read_deadline_method,
            c.response_read_deadline_route_method);
    const bool common_request =
        c.protocol == ConnProtocol::Http11 && !c.tls_active && c.h2 == nullptr &&
        c.req_http_version == static_cast<u8>(HttpVersion::Http11) &&
        response_read_deadline_persistence_owner_is_stable(c, c.response_read_deadline_upload) &&
        !c.req_client_has_transfer_encoding && !c.req_client_has_te && !c.req_client_has_expect &&
        !c.req_client_has_upgrade_header && !c.req_malformed && !c.req_wants_upgrade &&
        c.req_path_canon.ptr != nullptr && pipeline_generation_stable &&
        !c.target_transform_recorded && !c.req_path_overridden &&
        c.req_header_override_count == 0 && !c.req_header_override_overflow &&
        c.resp_header_mutation_count == 0 && c.resp_header_mutation_pending_count == 0 &&
        !c.resp_header_mutation_pending_overflow && !c.resp_header_mutation_overflow;
    if (!common_request) return false;
    const bool coalesced_get = response_read_deadline_coalesced_get_phase1_stash_is_stable(
        c, c.response_read_deadline_upload);
    if (c.pipeline_stash_len != 0 && !coalesced_get) return false;
    const bool complete_buffering =
        c.response_read_deadline_buffering == ForwardResponseBufferingMode::CompleteContentLength;
    const bool fixed_upload =
        response_read_deadline_profile_is_fixed_upload(c.response_read_deadline_profile);
    const bool suppresses_head =
        response_read_deadline_profile_suppresses_head(c.response_read_deadline_profile);
    if (fixed_upload && suppresses_head) {
        if (c.response_read_deadline_profile !=
                ResponseReadDeadlineProfile::FixedContentLengthUploadHeaderOnlyHead ||
            complete_buffering || c.req_method != static_cast<u8>(LogHttpMethod::Head) ||
            !c.req_client_has_content_length || c.req_body_mode != BodyMode::ContentLength ||
            c.req_body_remaining != 0 || !c.request_body_fully_buffered || c.req_body_streamed ||
            !c.response_policy_suppress_body || !c.failure_policy_suppress_body ||
            response.head_mode != ResponsePolicyHeadMode::SuppressBody ||
            failure.head_mode != FailurePolicyHeadMode::SuppressBody ||
            timeout.head_mode != FailurePolicyHeadMode::SuppressBody || c.retry_req_send_len != 0 ||
            c.response_mutations_snapshotted ||
            !response_read_deadline_fixed_upload_proof_is_stable(c,
                                                                 c.response_read_deadline_upload))
            return false;
    } else if (suppresses_head) {
        if (c.req_method != static_cast<u8>(LogHttpMethod::Head) ||
            c.req_client_has_content_length || c.req_body_mode != BodyMode::None ||
            c.req_body_remaining != 0 || c.request_body_fully_buffered || c.req_body_streamed ||
            !c.response_policy_suppress_body || !c.failure_policy_suppress_body ||
            response.head_mode != ResponsePolicyHeadMode::SuppressBody ||
            failure.head_mode != FailurePolicyHeadMode::SuppressBody ||
            timeout.head_mode != FailurePolicyHeadMode::SuppressBody)
            return false;
    } else if (c.response_read_deadline_profile ==
               ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero) {
        if (!response_read_deadline_non_head_method_admitted(c.response_read_deadline_method) ||
            c.req_client_has_content_length || c.req_body_mode != BodyMode::None ||
            c.req_body_remaining != 0 || c.request_body_fully_buffered || c.req_body_streamed ||
            c.response_policy_suppress_body || c.failure_policy_suppress_body ||
            response.head_mode != ResponsePolicyHeadMode::Reject ||
            failure.head_mode != FailurePolicyHeadMode::Reject ||
            timeout.head_mode != FailurePolicyHeadMode::Reject)
            return false;
    } else if (fixed_upload) {
        if (!(complete_buffering
                  ? complete_content_length_fixed_upload_composition_is_stable(
                        c, c.response_read_deadline_upload, /*require_upload_complete=*/true)
                  : response_read_deadline_fixed_upload_proof_is_stable(
                        c, c.response_read_deadline_upload)) ||
            c.response_policy_suppress_body || c.failure_policy_suppress_body ||
            response.head_mode != ResponsePolicyHeadMode::Reject ||
            failure.head_mode != FailurePolicyHeadMode::Reject ||
            timeout.head_mode != FailurePolicyHeadMode::Reject)
            return false;
    } else {
        return false;
    }
    const bool post_commit =
        c.response_read_deadline_post_commit_phase != ResponseReadDeadlinePostCommitPhase::None;
    const bool bodyless_post_commit = c.response_read_deadline_profile ==
                                      ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero;
    const bool fixed_upload_post_commit =
        complete_buffering &&
        response_read_deadline_profile_is_fixed_upload(c.response_read_deadline_profile) &&
        complete_content_length_fixed_upload_composition_is_stable(
            c, c.response_read_deadline_upload, /*require_upload_complete=*/true);
    const bool post_commit_owner =
        post_commit &&
        c.response_read_deadline_post_commit_generation == c.response_read_deadline_generation &&
        c.response_read_deadline_post_commit_episode == c.upstream_episode &&
        (bodyless_post_commit || fixed_upload_post_commit) &&
        ((complete_buffering &&
          response_read_deadline_non_head_method_admitted(c.response_read_deadline_method) &&
          complete_content_length_route_method_is_admitted(
              c.response_read_deadline_route_method)) ||
         (!complete_buffering &&
          c.response_read_deadline_method == static_cast<u8>(LogHttpMethod::Get))) &&
        response_read_deadline_route_method_matches(c.response_read_deadline_method,
                                                    c.response_read_deadline_route_method) &&
        c.response_read_deadline_post_commit_declared_body != 0 &&
        c.response_read_deadline_post_commit_raw_header_end != 0 &&
        c.response_read_deadline_post_commit_origin_received <=
            c.response_read_deadline_post_commit_declared_body &&
        c.response_read_deadline_post_commit_downstream_completed <=
            c.response_read_deadline_post_commit_downstream_submitted &&
        c.response_read_deadline_post_commit_downstream_submitted <=
            c.response_read_deadline_post_commit_origin_received &&
        c.response_read_deadline_post_commit_inflight_body <=
            c.response_read_deadline_post_commit_downstream_submitted -
                c.response_read_deadline_post_commit_downstream_completed;
    if (post_commit && !post_commit_owner) return false;
    if (complete_buffering && !bodyless_post_commit && !fixed_upload_post_commit) return false;
    if (complete_buffering) {
        const bool collecting = c.response_read_deadline_post_commit_phase ==
                                ResponseReadDeadlinePostCommitPhase::Buffering;
        if (!complete_content_length_route_method_is_admitted(
                c.response_read_deadline_route_method) ||
            c.response_read_deadline_post_commit_send_body >
                c.response_read_deadline_post_commit_origin_received ||
            (collecting && (c.response_read_deadline_post_commit_send_body != 0 ||
                            c.response_read_deadline_post_commit_close_after_drain ||
                            c.response_read_deadline_post_commit_downstream_submitted != 0 ||
                            c.response_read_deadline_post_commit_downstream_completed != 0)) ||
            (!collecting && !c.response_read_deadline_post_commit_close_after_drain &&
             (c.response_read_deadline_post_commit_send_body !=
                  c.response_read_deadline_post_commit_declared_body ||
              c.response_read_deadline_post_commit_origin_received !=
                  c.response_read_deadline_post_commit_declared_body)))
            return false;
    } else if (c.response_read_deadline_post_commit_send_body != 0 ||
               c.response_read_deadline_post_commit_close_after_drain) {
        return false;
    }
    if (c.upstream_idx >= cfg->upstream_count || cfg->upstreams[c.upstream_idx].addr_count != 1 ||
        cfg->upstreams[c.upstream_idx].addrs[0].sin_family != AF_INET || c.upstream_attempts != 1 ||
        c.upstream_reused || !c.request_upload_complete || c.upstream_request_incomplete ||
        (!post_commit && c.on_upstream_recv != expected_upstream_recv) ||
        (post_commit && c.on_upstream_recv != nullptr &&
         c.on_upstream_recv != expected_upstream_recv) ||
        c.on_upstream_send != nullptr || c.upstream_fd < 0 ||
        !valid_upstream_episode(c.upstream_episode) || c.upstream_episode_quarantined ||
        c.upstream_connect_armed || c.upstream_send_armed ||
        (!post_commit && c.upstream_recv_paused_for_send) || c.upstream_recv_pause_cancel_pending ||
        c.upstream_recv_pause_rearm_pending || c.upstream_recv_cancel_inflight ||
        c.upstream_retirement_active || c.upstream_retirement_target_owned != 0 ||
        c.upstream_retirement_cancel_owned != 0 || c.upstream_retirement_cancel_retry != 0 ||
        c.upstream_close_episode != 0 || c.upstream_close_target_owned != 0 ||
        c.upstream_close_cancel_owned != 0 || c.upstream_close_pause_cancel_owned ||
        c.idle_return_fd >= 0 || c.idle_return_config != nullptr || c.close_after_idle_return)
        return false;
    if (phase == ResponseReadDeadlineOwnerPhase::ValidatedBeforeArm)
        return c.response_read_deadline_state == ResponseReadDeadlineState::Validated &&
               c.response_read_deadline_upstream_episode == 0 && !c.upstream_recv_armed &&
               c.upstream_recv_buf.len() == 0;
    const bool state_ok =
        phase == ResponseReadDeadlineOwnerPhase::ArmedForCopy
            ? c.response_read_deadline_state == ResponseReadDeadlineState::Armed ||
                  (post_commit &&
                   c.response_read_deadline_state == ResponseReadDeadlineState::BodyComplete)
            : c.response_read_deadline_state == ResponseReadDeadlineState::Armed ||
                  c.response_read_deadline_state == ResponseReadDeadlineState::ExpiryPending ||
                  c.response_read_deadline_state == ResponseReadDeadlineState::BatchPending ||
                  c.response_read_deadline_state == ResponseReadDeadlineState::RefreshPending ||
                  (post_commit &&
                   c.response_read_deadline_state == ResponseReadDeadlineState::BodyComplete);
    return state_ok && c.response_read_deadline_upstream_episode == c.upstream_episode &&
           (phase == ResponseReadDeadlineOwnerPhase::ActiveAfterCopy || c.upstream_recv_armed);
}

inline bool header_only_head_keep_alive_arm_is_stable(const Connection& c,
                                                      const ResponseReadDeadlineUploadProof& proof,
                                                      const RouteConfig* config,
                                                      u16 bundle_id,
                                                      ResponseReadDeadlineOwnerPhase phase,
                                                      Connection::Callback expected_upstream_recv) {
    if (config == nullptr || config != c.request_config ||
        c.response_read_deadline_profile != ResponseReadDeadlineProfile::HeaderOnlyHead ||
        c.response_read_deadline_buffering != ForwardResponseBufferingMode::None ||
        c.response_read_deadline_method != static_cast<u8>(LogHttpMethod::Head) ||
        c.req_method != c.response_read_deadline_method || proof.downstream_close ||
        !response_read_deadline_default_persistence_is_stable(c) || c.pipeline_depth != 0 ||
        c.http1_pipeline_request_generation != 0 || c.response_mutations_snapshotted ||
        c.retry_req_send_len != 0 ||
        c.request_policy_id != static_cast<u16>(RequestPolicyId::Http11FixedStrip) ||
        proof.request_policy_id != c.request_policy_id || proof.handler_generation == 0 ||
        proof.handler_generation != c.handler_gen || proof.route_index >= config->route_count ||
        proof.route_fn == nullptr || proof.upstream_id >= config->upstream_count ||
        proof.upstream_id != c.upstream_idx || proof.raw_header_end == 0 ||
        proof.raw_content_length != 0 || proof.raw_total_length != proof.raw_header_end ||
        proof.rewritten_header_end == 0 || proof.rewritten_header_end != c.req_header_end ||
        proof.rewritten_total_length != c.req_initial_send_len ||
        proof.rewritten_total_length != proof.rewritten_header_end ||
        proof.expected_upload_length != proof.rewritten_total_length ||
        !valid_upstream_episode(proof.upload_episode) ||
        proof.upload_episode != c.upstream_episode || c.upstream_abandoned ||
        !response_read_deadline_owner_is_stable(c, expected_upstream_recv, phase))
        return false;
    const RouteEntry& route = config->routes[proof.route_index];
    const UpstreamTarget& target = config->upstreams[proof.upstream_id];
    RouteParam params[kMaxRouteParams]{};
    u32 param_count = 0;
    return c.response_read_deadline_bundle_id == bundle_id &&
           route.action == RouteAction::JitHandler && route.fn == proof.route_fn &&
           route.method == c.response_read_deadline_route_method && !route.needs_req_body &&
           route.rate_limit.count == 0 && route.throttle_down_bps == 0 && !route.ws_terminate &&
           forward_preflight_mode_can_own_runtime_deadline(route.forward_preflight_mode) &&
           route.preflight_forward_policy_bundle_id == bundle_id && target.addr_count == 1 &&
           target.addrs[0].sin_family == AF_INET && target.max_inflight == 0 &&
           config->match_canonical(c.req_path_canon,
                                   route_method_key(static_cast<LogHttpMethod>(c.req_method)),
                                   params,
                                   &param_count,
                                   kMaxRouteParams) == &route;
}

inline bool bodyless_get_keep_alive_precise_arm_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& proof,
    const RouteConfig* config,
    u16 bundle_id,
    ResponseReadDeadlineOwnerPhase phase,
    Connection::Callback expected_upstream_recv) {
    if (config == nullptr || config != c.request_config ||
        c.response_read_deadline_profile !=
            ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero ||
        c.response_read_deadline_buffering != ForwardResponseBufferingMode::CompleteContentLength ||
        c.response_read_deadline_method != static_cast<u8>(LogHttpMethod::Get) ||
        c.response_read_deadline_route_method != kRouteMethodGet ||
        c.req_method != c.response_read_deadline_method || proof.downstream_close ||
        !response_read_deadline_default_persistence_is_stable(c) || c.pipeline_depth != 0 ||
        c.http1_pipeline_request_generation != 0 || c.pipeline_stash_len != 0 ||
        c.response_read_deadline_post_commit_phase != ResponseReadDeadlinePostCommitPhase::None ||
        c.response_mutations_snapshotted || c.retry_req_send_len != 0 ||
        c.request_policy_id != static_cast<u16>(RequestPolicyId::Http11FixedStrip) ||
        proof.request_policy_id != c.request_policy_id || proof.handler_generation == 0 ||
        proof.handler_generation != c.handler_gen || proof.route_index >= config->route_count ||
        proof.route_fn == nullptr || proof.upstream_id >= config->upstream_count ||
        proof.upstream_id != c.upstream_idx || proof.raw_header_end == 0 ||
        proof.raw_content_length != 0 || proof.raw_total_length != proof.raw_header_end ||
        proof.rewritten_header_end == 0 || proof.rewritten_header_end != c.req_header_end ||
        proof.rewritten_total_length != c.req_initial_send_len ||
        proof.rewritten_total_length != proof.rewritten_header_end ||
        proof.expected_upload_length != proof.rewritten_total_length ||
        !valid_upstream_episode(proof.upload_episode) ||
        proof.upload_episode != c.upstream_episode || c.upstream_abandoned ||
        c.req_client_content_length_count != 0 || c.req_client_has_content_length ||
        !response_read_deadline_owner_is_stable(c, expected_upstream_recv, phase))
        return false;
    const RouteEntry& route = config->routes[proof.route_index];
    const UpstreamTarget& target = config->upstreams[proof.upstream_id];
    RouteParam params[kMaxRouteParams]{};
    u32 param_count = 0;
    return c.response_read_deadline_bundle_id == bundle_id &&
           route.action == RouteAction::JitHandler && route.fn == proof.route_fn &&
           route.method == kRouteMethodGet && !route.needs_req_body &&
           route.rate_limit.count == 0 && route.throttle_down_bps == 0 && !route.ws_terminate &&
           forward_preflight_mode_can_own_runtime_deadline(route.forward_preflight_mode) &&
           route.preflight_forward_policy_bundle_id == bundle_id && target.addr_count == 1 &&
           target.addrs[0].sin_family == AF_INET && target.max_inflight == 0 &&
           config->match_canonical(c.req_path_canon,
                                   route_method_key(static_cast<LogHttpMethod>(c.req_method)),
                                   params,
                                   &param_count,
                                   kMaxRouteParams) == &route;
}

inline bool response_read_deadline_post_commit_is_stable(const Connection& c) {
    const RouteConfig* cfg = c.request_config;
    const u16 bundle_id = c.response_read_deadline_bundle_id;
    const bool complete_buffering =
        c.response_read_deadline_buffering == ForwardResponseBufferingMode::CompleteContentLength;
    const bool retired_buffered_send =
        complete_buffering && c.response_read_deadline_post_commit_phase !=
                                  ResponseReadDeadlinePostCommitPhase::Buffering;
    const bool pipeline_generation_stable =
        http1_pipeline_request_generation_upload_active_is_stable(
            c,
            c.response_read_deadline_upload,
            c.response_read_deadline_profile,
            c.response_read_deadline_buffering,
            c.response_read_deadline_method,
            c.response_read_deadline_route_method,
            retired_buffered_send);
    const bool fixed_upload =
        response_read_deadline_profile_is_fixed_upload(c.response_read_deadline_profile);
    const bool episode_stable =
        retired_buffered_send
            ? c.response_read_deadline_post_commit_episode == c.upstream_retiring_episode &&
                  c.upstream_fd < 0 && c.upstream_abandoned &&
                  valid_upstream_episode(c.upstream_episode)
            : c.response_read_deadline_post_commit_episode == c.upstream_episode &&
                  c.upstream_fd >= 0 && valid_upstream_episode(c.upstream_episode);
    const bool profile_stable =
        fixed_upload
            ? complete_buffering && complete_content_length_fixed_upload_composition_is_stable(
                                        c,
                                        c.response_read_deadline_upload,
                                        /*require_upload_complete=*/true,
                                        /*retired_episode=*/retired_buffered_send)
            : c.response_read_deadline_profile ==
                      ResponseReadDeadlineProfile::BodylessNonHeadContentLengthZero &&
                  (complete_buffering
                       ? response_read_deadline_non_head_method_admitted(
                             c.response_read_deadline_method) &&
                             complete_content_length_route_method_is_admitted(
                                 c.response_read_deadline_route_method)
                       : c.response_read_deadline_method == static_cast<u8>(LogHttpMethod::Get));
    if (cfg == nullptr || !cfg->policy_bundle_id_is_valid(bundle_id) ||
        c.response_read_deadline_post_commit_phase == ResponseReadDeadlinePostCommitPhase::None ||
        c.response_read_deadline_post_commit_generation == 0 ||
        c.response_read_deadline_post_commit_generation != c.response_read_deadline_generation ||
        !episode_stable || !profile_stable || c.response_read_deadline_method != c.req_method ||
        !response_read_deadline_route_method_matches(c.req_method,
                                                     c.response_read_deadline_route_method) ||
        c.response_read_deadline_post_commit_raw_header_end == 0 ||
        c.response_read_deadline_post_commit_declared_body == 0 ||
        c.response_read_deadline_post_commit_raw_header_end > c.upstream_recv_buf.capacity() ||
        c.response_read_deadline_post_commit_declared_body >
            c.upstream_recv_buf.capacity() - c.response_read_deadline_post_commit_raw_header_end ||
        c.response_read_deadline_post_commit_origin_received >
            c.response_read_deadline_post_commit_declared_body ||
        c.response_read_deadline_post_commit_downstream_completed >
            c.response_read_deadline_post_commit_downstream_submitted ||
        c.response_read_deadline_post_commit_downstream_submitted >
            c.response_read_deadline_post_commit_origin_received ||
        c.response_read_deadline_post_commit_inflight_body >
            c.response_read_deadline_post_commit_downstream_submitted -
                c.response_read_deadline_post_commit_downstream_completed ||
        c.protocol != ConnProtocol::Http11 || c.tls_active || c.h2 != nullptr ||
        c.req_http_version != static_cast<u8>(HttpVersion::Http11) ||
        !response_read_deadline_persistence_owner_is_stable(c, c.response_read_deadline_upload) ||
        (!fixed_upload && c.req_client_has_content_length) || c.req_client_has_transfer_encoding ||
        c.req_client_has_te || c.req_client_has_expect || c.req_client_has_upgrade_header ||
        (fixed_upload ? c.req_body_mode != BodyMode::ContentLength || c.req_body_remaining != 0 ||
                            !c.request_body_fully_buffered
                      : c.req_body_mode != BodyMode::None || c.req_body_remaining != 0 ||
                            c.request_body_fully_buffered) ||
        c.req_body_streamed || c.req_malformed || c.req_wants_upgrade ||
        !pipeline_generation_stable || c.target_transform_recorded || c.req_path_overridden ||
        c.req_header_override_count != 0 || c.req_header_override_overflow ||
        c.resp_header_mutation_count != 0 || c.resp_header_mutation_pending_count != 0 ||
        c.resp_header_mutation_pending_overflow || c.resp_header_mutation_overflow ||
        c.upstream_reused || c.upstream_attempts != 1 || !c.request_upload_complete ||
        c.upstream_request_incomplete)
        return false;
    if (c.pipeline_stash_len != 0 && !response_read_deadline_coalesced_get_phase1_stash_is_stable(
                                         c, c.response_read_deadline_upload, retired_buffered_send))
        return false;
    if (!complete_content_length_request_policy_owner_is_stable(c, c.response_read_deadline_upload))
        return false;
    const auto& bundle = cfg->policy_bundles[bundle_id - 1];
    const bool collecting = c.response_read_deadline_post_commit_phase ==
                            ResponseReadDeadlinePostCommitPhase::Buffering;
    if (complete_buffering) {
        if (!complete_content_length_route_method_is_admitted(
                c.response_read_deadline_route_method) ||
            !complete_content_length_pinned_header_is_stable(c) ||
            c.response_read_deadline_post_commit_send_body >
                c.response_read_deadline_post_commit_origin_received ||
            (collecting && (c.response_read_deadline_post_commit_send_body != 0 ||
                            c.response_read_deadline_post_commit_close_after_drain ||
                            c.response_read_deadline_post_commit_downstream_submitted != 0 ||
                            c.response_read_deadline_post_commit_downstream_completed != 0)) ||
            (!collecting && !c.response_read_deadline_post_commit_close_after_drain &&
             (c.response_read_deadline_post_commit_send_body !=
                  c.response_read_deadline_post_commit_declared_body ||
              c.response_read_deadline_post_commit_origin_received !=
                  c.response_read_deadline_post_commit_declared_body)))
            return false;
    } else if (c.response_read_deadline_post_commit_send_body != 0 ||
               c.response_read_deadline_post_commit_close_after_drain) {
        return false;
    }
    if (complete_buffering &&
        (!cfg->response_policy_id_is_valid(bundle.response_policy_id) ||
         !cfg->failure_policy_id_is_valid(bundle.failure_policy_id) ||
         !cfg->timeout_failure_policy_id_is_valid(bundle.timeout_failure_policy_id) ||
         !complete_content_length_buffering_policies_valid(
             cfg->response_policies[bundle.response_policy_id - 1],
             cfg->failure_policies[bundle.failure_policy_id - 1],
             cfg->failure_policies[bundle.timeout_failure_policy_id - 1])))
        return false;
    return response_read_timeout_seconds_valid(bundle.response_read_timeout_seconds) &&
           bundle.response_read_timeout_seconds == c.response_read_deadline_seconds &&
           bundle.response_buffering == c.response_read_deadline_buffering &&
           bundle.response_policy_id == c.response_policy_id &&
           bundle.failure_policy_id == c.failure_policy_id &&
           bundle.timeout_failure_policy_id == c.timeout_failure_policy_id &&
           cfg->response_policy_id_is_valid(bundle.response_policy_id) &&
           cfg->failure_policy_id_is_valid(bundle.failure_policy_id) &&
           cfg->timeout_failure_policy_id_is_valid(bundle.timeout_failure_policy_id);
}

}  // namespace rut
