#pragma once

#include "rut/runtime/https_fetch.h"
#include "rut/runtime/json.h"

namespace rut {
// Trusted, fixed-endpoint refresh controls shared by asymmetric JWT policies.
// Parsing occurs before configuration publication, never from token metadata.
struct RemoteJwks {
    HttpsEndpoint endpoint{};
    char dns_address[16]{};
    u16 dns_port = 53;
    char allowed_addresses[8][16]{};
    u32 allowed_count = 0;
    char discovery_path[1024]{};
    char discovery_issuer[1024]{};
    u32 refresh_seconds = 0;
    u32 max_age_seconds = 0;
    u32 timeout_seconds = 0;
    bool enabled() const { return refresh_seconds != 0; }
    bool load(json::Document& document, u32 node);
};

// Shared cold, nonblocking resolver/discovery/JWKS lifecycle. Only configured
// addresses and URI are admitted; token metadata never selects a destination.
class JwksFetch {
public:
    using State = HttpsFetch::State;
    ~JwksFetch();
    bool init(const RemoteJwks& configuration);
    bool start(u64 monotonic_ms, u32 timeout_ms);
    void advance(u64 monotonic_ms);
    void cancel();
    State state() const { return state_; }
    Str body() const { return state_ == State::Done ? keys_.body() : Str{}; }

private:
    RemoteJwks configuration_{};
    HttpsFetch keys_;
    HttpsFetch discovery_;
    State state_ = State::Idle;
    i32 dns_fd_ = -1;
    u8 query_[272]{};
    u32 query_length_ = 0;
    u64 started_ = 0;
    u32 timeout_ = 0;
    bool discovering_ = false;
    bool begin_http(u64 now);
    bool fail();
};
// Exposed for deterministic wire/metadata rejection tests, no I/O.
bool jwks_discovery_valid(json::Document& document, Str body, const RemoteJwks& configuration);
bool jwks_dns_answer(Str packet, Str query, const RemoteJwks& configuration, char (&address)[16]);
}  // namespace rut
