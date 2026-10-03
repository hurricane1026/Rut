#pragma once

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/error.h"

namespace rut {

struct ListenerSpec;

// Create a listen socket.
// Returns fd on success, Error on failure.
// reuse_port enables SO_REUSEPORT on Linux so shards can share a port.
// Pass false for an exclusive listener (including a single-shard server).
core::Expected<i32, Error> create_listen_socket(const ListenerSpec& declared,
                                                u16 requested_port,
                                                bool reuse_port = true);

// Behavior-compatible IPv4-wildcard wrapper for legacy callers.
core::Expected<i32, Error> create_listen_socket(u16 port);

// Set fd to non-blocking mode.
core::Expected<void, Error> set_nonblocking(i32 fd);

}  // namespace rut
