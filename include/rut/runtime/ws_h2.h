#pragma once

#include "rut/runtime/connection.h"

namespace rut {
struct GrpcExchange;
struct RouteEntry;

// A callback context belongs to one WebSocket stream, never to the multiplexed
// socket. The embedded Connection supplies the existing helper ABI, peer facts,
// owned JSON workspace, inspectors and codec storage; it performs no socket I/O.
struct WsH2Session {
    Connection callback;
    u32 output_length[2]{};  // client->upstream, upstream->client
    u32 output_offset[2]{};
    bool output_close[2]{};
    bool close_staged[2]{};
    u64 close_deadline_us = 0;
    bool ready = false;
};

WsH2Session* ws_h2_create(SlicePool&, const RouteEntry&, const Connection&);
void ws_h2_destroy(SlicePool&, WsH2Session*);
bool ws_h2_prepare_request(WsH2Session&, const ParsedRequest&, ParsedRequest*);
bool ws_h2_accept(WsH2Session&, SlicePool&, const Header*, u32);
bool ws_h2_open(GrpcExchange&);
bool ws_h2_process(GrpcExchange&, bool from_client);
void ws_h2_eof(GrpcExchange&, bool from_client);
const u8* ws_h2_output(GrpcExchange&, bool from_client, u32* length);
bool ws_h2_consume_output(GrpcExchange&, bool from_client, u32 length);
void ws_h2_sent(GrpcExchange&, bool from_client);
void ws_h2_update_end(GrpcExchange&);
}  // namespace rut
