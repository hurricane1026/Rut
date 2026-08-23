#pragma once

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
    const auto& bundle = cfg->policy_bundles[bundle_id - 1];
    if (!response_read_timeout_seconds_valid(bundle.response_read_timeout_seconds) ||
        bundle.response_read_timeout_seconds != c.response_read_deadline_seconds ||
        bundle.response_policy_id != c.response_policy_id ||
        bundle.failure_policy_id != c.failure_policy_id ||
        bundle.timeout_failure_policy_id != c.timeout_failure_policy_id ||
        !cfg->response_policy_id_is_valid(bundle.response_policy_id) ||
        !cfg->failure_policy_id_is_valid(bundle.failure_policy_id) ||
        !cfg->timeout_failure_policy_id_is_valid(bundle.timeout_failure_policy_id))
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
        c.req_http_version == static_cast<u8>(HttpVersion::Http11) && c.req_keep_alive &&
        c.req_client_keep_alive && !c.req_client_connection_close &&
        !c.req_client_connection_close_exact && c.req_client_connection_count == 0 &&
        !c.req_client_has_content_length && !c.req_client_has_transfer_encoding &&
        !c.req_client_has_te && !c.req_client_has_expect && !c.req_client_has_upgrade_header &&
        !c.req_malformed && !c.req_wants_upgrade && c.req_path_canon.ptr != nullptr &&
        c.req_body_mode == BodyMode::None && c.req_body_remaining == 0 &&
        !c.request_body_fully_buffered && !c.req_body_streamed && c.pipeline_depth == 0 &&
        c.pipeline_stash_len == 0 && !c.target_transform_recorded && !c.req_path_overridden &&
        c.req_header_override_count == 0 && !c.req_header_override_overflow &&
        c.resp_header_mutation_count == 0 && c.resp_header_mutation_pending_count == 0 &&
        !c.resp_header_mutation_pending_overflow && !c.resp_header_mutation_overflow;
    if (!common_request) return false;
    if (c.response_read_deadline_profile == ResponseReadDeadlineProfile::HeaderOnlyHead) {
        if (c.req_method != static_cast<u8>(LogHttpMethod::Head) ||
            !c.response_policy_suppress_body || !c.failure_policy_suppress_body ||
            response.head_mode != ResponsePolicyHeadMode::SuppressBody ||
            failure.head_mode != FailurePolicyHeadMode::SuppressBody ||
            timeout.head_mode != FailurePolicyHeadMode::SuppressBody)
            return false;
    } else if (c.response_read_deadline_profile ==
               ResponseReadDeadlineProfile::BodylessGetContentLengthZero) {
        if (c.req_method != static_cast<u8>(LogHttpMethod::Get) ||
            c.response_policy_suppress_body || c.failure_policy_suppress_body ||
            response.head_mode != ResponsePolicyHeadMode::Reject ||
            failure.head_mode != FailurePolicyHeadMode::Reject ||
            timeout.head_mode != FailurePolicyHeadMode::Reject)
            return false;
    } else {
        return false;
    }
    if (c.upstream_idx >= cfg->upstream_count || cfg->upstreams[c.upstream_idx].addr_count != 1 ||
        cfg->upstreams[c.upstream_idx].addrs[0].sin_family != AF_INET || c.upstream_attempts != 1 ||
        c.upstream_reused || !c.request_upload_complete || c.upstream_request_incomplete ||
        c.on_upstream_recv != expected_upstream_recv || c.on_upstream_send != nullptr ||
        c.upstream_fd < 0 || !valid_upstream_episode(c.upstream_episode) ||
        c.upstream_episode_quarantined || c.upstream_connect_armed || c.upstream_send_armed ||
        c.upstream_recv_paused_for_send || c.upstream_recv_pause_cancel_pending ||
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
            ? c.response_read_deadline_state == ResponseReadDeadlineState::Armed
            : c.response_read_deadline_state == ResponseReadDeadlineState::Armed ||
                  c.response_read_deadline_state == ResponseReadDeadlineState::ExpiryPending ||
                  c.response_read_deadline_state == ResponseReadDeadlineState::BatchPending ||
                  c.response_read_deadline_state == ResponseReadDeadlineState::RefreshPending;
    return state_ok && c.response_read_deadline_upstream_episode == c.upstream_episode &&
           (phase == ResponseReadDeadlineOwnerPhase::ActiveAfterCopy || c.upstream_recv_armed);
}

}  // namespace rut
