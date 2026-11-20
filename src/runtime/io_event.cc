#include "rut/runtime/io_event.h"

namespace rut {
namespace {

// Compare to the wire layout independently of the encoder, so a matching
// change in the encoder and decoder cannot silently move a field.
consteval bool upstream_token_matches(IoEventType type, u32 id, u32 episode, u8 aux) {
    const u64 wire =
        (u64{aux} << 56) | (u64{episode} << 32) | (u64{id} << 8) | static_cast<u8>(type);
    NonUpstreamUserData other{};
    if (decode_non_upstream_user_data(wire, &other)) return false;
    const auto completion = decode_upstream_completion_token(wire);
    UpstreamEventToken checked{};
    IoEvent event{};
    event.type = completion.type;
    event.upstream_episode = completion.episode;
    if (completion.type != type || completion.conn_id != id || completion.aux != aux) return false;
    if (!episode) {
        return !decode_upstream_event_token(wire, &checked) &&
               encode_upstream_event_token({id, type, episode, aux}) == kInvalidIoUserData &&
               completion.episode == kInvalidUpstreamEventEpisode &&
               io_event_is_tagged_stale(event, 0) && io_event_is_tagged_stale(event, 1) &&
               io_event_is_tagged_stale(event, kInvalidUpstreamEventEpisode);
    }
    return encode_upstream_event_token({id, type, episode, aux}) == wire &&
           decode_upstream_event_token(wire, &checked) && checked.conn_id == id &&
           checked.type == type && checked.aux == aux && checked.episode == episode &&
           completion.episode == episode && !io_event_is_tagged_stale(event, episode) &&
           io_event_is_tagged_stale(event, episode == 1 ? 2 : 1);
}

consteval bool upstream_wire_contract() {
    constexpr IoEventType types[] = {IoEventType::UpstreamConnect,
                                     IoEventType::UpstreamRecv,
                                     IoEventType::UpstreamSend,
                                     IoEventType::RelayRead,
                                     IoEventType::RelayWrite};
    for (auto type : types) {
        if (encode_upstream_event_token({0x1000000, type, 1, 0}) != kInvalidIoUserData ||
            encode_upstream_event_token({0, type, 0x1000000, 0}) != kInvalidIoUserData)
            return false;
        if (!upstream_token_matches(type, 0xffffff, 0xffffff, 0xff) ||
            !upstream_token_matches(type, 0x123456, 0, kUpstreamCloseCancelAux))
            return false;
        for (unsigned bit = 0; bit < 24; ++bit) {
            if (!upstream_token_matches(type, 1u << bit, 1, 0) ||
                !upstream_token_matches(type, 0, 1u << bit, 0))
                return false;
        }
        for (unsigned bit = 0; bit < 8; ++bit)
            if (!upstream_token_matches(type, 0, 1, static_cast<u8>(1u << bit))) return false;
    }
    // Every wire tag is either an episode event or must be rejected by this codec.
    for (unsigned tag = 0; tag <= 255; ++tag) {
        const auto type = static_cast<IoEventType>(tag);
        bool expected = false;
        for (auto upstream : types) expected |= type == upstream;
        if (io_event_uses_upstream_episode(type) != expected) return false;
        UpstreamEventToken checked{};
        if (decode_upstream_event_token((u64{1} << 32) | tag, &checked) != expected) return false;
    }
    return true;
}

static_assert(upstream_wire_contract(),
              "Upstream completion token violates wire or episode contract");

}  // namespace
}  // namespace rut
