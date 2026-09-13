#pragma once

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/error.h"

namespace rut {

struct ListenerSpec;

// Create a non-blocking, reusable listen socket.
// Returns fd on success, Error on failure.
// Uses SO_REUSEPORT so each shard can bind the same port.
core::Expected<i32, Error> create_listen_socket(const ListenerSpec& declared, u16 requested_port);

// Behavior-compatible IPv4-wildcard wrapper for legacy callers.
core::Expected<i32, Error> create_listen_socket(u16 port);

// Set fd to non-blocking mode.
core::Expected<void, Error> set_nonblocking(i32 fd);

}  // namespace rut
