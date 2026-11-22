#pragma once

#include "rut/runtime/https_fetch.h"
#include "rut/runtime/json.h"

namespace rut {
// Trusted, fixed-endpoint refresh controls shared by asymmetric JWT policies.
// Parsing occurs before configuration publication, never from token metadata.
struct RemoteJwks {
    static constexpr u32 kMaxDnsAddresses = 8;
    HttpsEndpoint endpoint{};
    char dns_address[HttpsEndpoint::kAddressCapacity]{};
    bool dns_aaaa = false;
    bool dns_dual_stack = false;
    u16 dns_port = 53;
    u32 dns_cache_seconds = 0;
    u32 dns_timeout_seconds = 0;
    char allowed_addresses[kMaxDnsAddresses][HttpsEndpoint::kAddressCapacity]{};
    u32 allowed_count = 0;
    char discovery_path[1024]{};
    char discovery_issuer[1024]{};
    u32 discovery_timeout_seconds = 0;
    u32 discovery_cache_seconds = 0;
    u32 refresh_seconds = 0;
    u32 retry_seconds = 0;
    u32 max_retry_seconds = 0;
    u32 max_retry_after_seconds = 0;
    bool require_non_empty_keys = false;
    bool conditional_requests = false;
    bool conditional_discovery = false;
    u32 max_age_seconds = 0;
    u32 timeout_seconds = 0;
    bool enabled() const { return refresh_seconds != 0; }
    bool load(json::Document& document, u32 node);
};

// Shard-local delay between failed attempts. A server hint does not affect
// the local backoff progression.
struct JwksRetry {
    u32 failure(const RemoteJwks& policy, u32 server_hint = 0);
    void reset() { local_seconds_ = 0; }

private:
    u32 local_seconds_ = 0;
};

struct JwksDnsAddresses {
    char values[RemoteJwks::kMaxDnsAddresses][HttpsEndpoint::kAddressCapacity]{};
    u32 count = 0;
    u32 ttl_seconds = 0;
};

// Owned validator bound to the accepted key representation and selected IP address.
struct JwksValidator {
    char tag[129]{};
    char address[HttpsEndpoint::kAddressCapacity]{};
    void clear();
    bool bind(Str entity_tag, Str selected_address);
    Str matching(Str selected_address) const;
};
bool jwks_response_etag(const ParsedResponse& response, Str& entity_tag);
u32 jwks_response_retry_after(const ParsedResponse& response, u32 cap_seconds);
bool jwks_cache_fresh(u64 now, u64 last_success, u32 max_age_seconds);

// Shared cold, nonblocking resolver/discovery/JWKS lifecycle. Only configured
// addresses and URI are admitted; token metadata never selects a destination.
class JwksFetch {
public:
    using State = HttpsFetch::State;
    ~JwksFetch();
    bool init(const RemoteJwks& configuration);
    bool start(u64 monotonic_ms,
               u32 timeout_ms,
               const JwksValidator* validator = nullptr,
               u64 validator_deadline = 0);
    void advance(u64 monotonic_ms);
    void finish_attempt();
    void cancel();
    State state() const { return state_; }
    bool not_modified() const { return state_ == State::Done && keys_.status() == 304; }
    const JwksValidator& validator() const { return response_validator_; }
    u32 retry_after_seconds() const { return retry_after_seconds_; }
    Str body() const { return state_ == State::Done ? keys_.body() : Str{}; }

private:
    RemoteJwks configuration_{};
    JwksValidator request_validator_{};
    JwksValidator response_validator_{};
    JwksValidator discovery_validator_{};
    char discovery_address_[HttpsEndpoint::kAddressCapacity]{};
    u64 discovery_accepted_at_ = 0;
    bool sent_discovery_validator_ = false;
    bool sent_validator_ = false;
    u64 validator_deadline_ = 0;
    u32 retry_after_seconds_ = 0;
    HttpsFetch keys_;
    HttpsFetch discovery_;
    State state_ = State::Idle;
    i32 dns_fd_ = -1;
    u8 query_[272]{};
    u32 query_length_ = 0;
    u64 started_ = 0;
    u32 timeout_ = 0;
    JwksDnsAddresses addresses_{};
    JwksDnsAddresses cached_addresses_{};
    u64 dns_cached_at_ = 0;
    u64 dns_cache_deadline_ = 0;
    u32 address_index_ = 0;
    bool discovering_ = false;
    bool initialized_ = false;
    bool send_dns_query(bool aaaa);
    bool begin_http(u64 now);
    bool start_http(HttpsFetch& fetch, u64 now);
    bool can_try_next_address(const HttpsFetch& fetch) const;
    Str selected_address() const;
    bool accept_discovery(u64 now);
    void clear_dns_cache();
    bool fail();
};
// Observe before checking deadlines so idle rows still detect clock resets.
bool jwks_observe_time(u64& previous_ms, u64 now_ms);

// Saturating completion-based maintenance deadline, shared by both JWT algorithms.
u64 jwks_refresh_deadline(u64 completed_ms, u32 interval_seconds);

// Exposed for deterministic wire/metadata rejection tests, no I/O.
bool jwks_discovery_valid(json::Document& document, Str body, const RemoteJwks& configuration);
bool jwks_dns_answer(Str packet,
                     Str query,
                     const RemoteJwks& configuration,
                     JwksDnsAddresses& addresses);
}  // namespace rut
