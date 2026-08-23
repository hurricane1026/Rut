#pragma once

#include "rut/common/request_policy.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/http_parser.h"
#include "rut/runtime/route_table.h"

#include <netinet/in.h>

namespace rut {

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

inline bool response_read_deadline_fixed_upload_method_admitted(u8 method) {
    switch (static_cast<LogHttpMethod>(method)) {
        case LogHttpMethod::Post:
        case LogHttpMethod::Put:
        case LogHttpMethod::Patch:
            return true;
        case LogHttpMethod::Get:
        case LogHttpMethod::Head:
        case LogHttpMethod::Delete:
        case LogHttpMethod::Options:
        case LogHttpMethod::Trace:
        case LogHttpMethod::Connect:
        case LogHttpMethod::Other:
            return false;
    }
    return false;
}

inline bool response_read_deadline_route_method_matches(u8 method, u8 route_method);

inline bool complete_content_length_pinned_header_is_stable(const Connection& c) {
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
        parsed.status_code != 200 || parsed.content_length_count != 1 || parsed.chunked ||
        parsed.headers_truncated ||
        parsed.content_length != c.response_read_deadline_post_commit_declared_body)
        return false;
    const auto& policy = c.request_config->response_policies[c.response_policy_id - 1];
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

inline bool response_read_deadline_persistence_owner_is_stable(
    const Connection& c, const ResponseReadDeadlineUploadProof& proof) {
    if (proof.downstream_close) return complete_content_length_explicit_close_is_stable(c, proof);
    return response_read_deadline_default_persistence_is_stable(c);
}

inline bool complete_content_length_request_policy_owner_is_stable(
    const Connection& c, const ResponseReadDeadlineUploadProof& proof) {
    if (c.response_read_deadline_buffering != ForwardResponseBufferingMode::CompleteContentLength)
        return true;
    if (c.response_read_deadline_profile ==
        ResponseReadDeadlineProfile::FixedContentLengthUploadNonHeadContentLengthZero) {
        return c.request_policy_id == static_cast<u16>(RequestPolicyId::Http11FixedStrip) &&
               proof.request_policy_id == c.request_policy_id;
    }
    return complete_content_length_request_policy_is_admitted(c.request_policy_id) &&
           proof.request_policy_id == c.request_policy_id;
}

inline bool response_read_deadline_fixed_upload_materialization_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& proof,
    bool require_upload_complete,
    u16 bundle_id,
    u8 route_method,
    bool allow_retired_episode = false) {
    const RouteConfig* cfg = c.request_config;
    if (cfg == nullptr || !response_read_deadline_fixed_upload_method_admitted(c.req_method) ||
        proof.handler_generation == 0 || proof.handler_generation != c.handler_gen ||
        proof.route_index >= cfg->route_count || proof.upstream_id >= cfg->upstream_count ||
        proof.request_policy_id == 0 || !request_policy_is_supported(proof.request_policy_id) ||
        proof.route_fn == nullptr || proof.raw_header_end == 0 || proof.raw_content_length == 0 ||
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
        require_upload_complete,
        c.response_read_deadline_bundle_id,
        c.response_read_deadline_route_method);
}

inline bool response_read_deadline_fixed_upload_proof_is_stable(
    const Connection& c, const ResponseReadDeadlineUploadProof& proof) {
    return response_read_deadline_fixed_upload_materialization_is_stable(
        c, proof, /*require_upload_complete=*/true);
}

// First-batch and D2 callers retain the immutable bundle/route identity after
// the live deadline latch may have moved phases. They prove CompleteContentLength
// at their boundary and use this helper for the exact policy/upload episode.
inline bool complete_content_length_fixed_upload_materialization_is_stable(
    const Connection& c,
    const ResponseReadDeadlineUploadProof& proof,
    bool require_upload_complete,
    u16 bundle_id,
    u8 route_method,
    bool retired_episode = false) {
    if (c.request_policy_id != static_cast<u16>(RequestPolicyId::Http11FixedStrip) ||
        proof.request_policy_id != c.request_policy_id ||
        !complete_content_length_route_method_is_admitted(route_method) ||
        !response_read_deadline_route_method_matches(c.req_method, route_method) ||
        !response_read_deadline_fixed_upload_materialization_is_stable(
            c, proof, require_upload_complete, bundle_id, route_method, retired_episode))
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
           c.response_read_deadline_profile ==
               ResponseReadDeadlineProfile::FixedContentLengthUploadNonHeadContentLengthZero &&
           complete_content_length_fixed_upload_materialization_is_stable(
               c, proof, require_upload_complete, bundle_id, route_method, retired_episode);
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
    const bool common_request =
        c.protocol == ConnProtocol::Http11 && !c.tls_active && c.h2 == nullptr &&
        c.req_http_version == static_cast<u8>(HttpVersion::Http11) &&
        response_read_deadline_persistence_owner_is_stable(c, c.response_read_deadline_upload) &&
        !c.req_client_has_transfer_encoding && !c.req_client_has_te && !c.req_client_has_expect &&
        !c.req_client_has_upgrade_header && !c.req_malformed && !c.req_wants_upgrade &&
        c.req_path_canon.ptr != nullptr && c.pipeline_depth == 0 && c.pipeline_stash_len == 0 &&
        !c.target_transform_recorded && !c.req_path_overridden &&
        c.req_header_override_count == 0 && !c.req_header_override_overflow &&
        c.resp_header_mutation_count == 0 && c.resp_header_mutation_pending_count == 0 &&
        !c.resp_header_mutation_pending_overflow && !c.resp_header_mutation_overflow;
    if (!common_request) return false;
    const bool complete_buffering =
        c.response_read_deadline_buffering == ForwardResponseBufferingMode::CompleteContentLength;
    if (c.response_read_deadline_profile == ResponseReadDeadlineProfile::HeaderOnlyHead) {
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
    } else if (c.response_read_deadline_profile ==
               ResponseReadDeadlineProfile::FixedContentLengthUploadNonHeadContentLengthZero) {
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
        c.response_read_deadline_profile ==
            ResponseReadDeadlineProfile::FixedContentLengthUploadNonHeadContentLengthZero &&
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

inline bool response_read_deadline_post_commit_is_stable(const Connection& c) {
    const RouteConfig* cfg = c.request_config;
    const u16 bundle_id = c.response_read_deadline_bundle_id;
    const bool complete_buffering =
        c.response_read_deadline_buffering == ForwardResponseBufferingMode::CompleteContentLength;
    const bool retired_buffered_send =
        complete_buffering && c.response_read_deadline_post_commit_phase !=
                                  ResponseReadDeadlinePostCommitPhase::Buffering;
    const bool fixed_upload =
        c.response_read_deadline_profile ==
        ResponseReadDeadlineProfile::FixedContentLengthUploadNonHeadContentLengthZero;
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
        c.req_body_streamed || c.req_malformed || c.req_wants_upgrade || c.pipeline_depth != 0 ||
        c.pipeline_stash_len != 0 || c.target_transform_recorded || c.req_path_overridden ||
        c.req_header_override_count != 0 || c.req_header_override_overflow ||
        c.resp_header_mutation_count != 0 || c.resp_header_mutation_pending_count != 0 ||
        c.resp_header_mutation_pending_overflow || c.resp_header_mutation_overflow ||
        c.upstream_reused || c.upstream_attempts != 1 || !c.request_upload_complete ||
        c.upstream_request_incomplete)
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
