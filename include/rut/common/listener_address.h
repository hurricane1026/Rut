#pragma once

#include "rut/common/types.h"

namespace rut {

// Listener addresses are immutable process-start metadata shared by the
// compiler-facing loader and the runtime. IPv4 values are stored in host byte
// order; for example, 127.0.0.1 is 0x7f000001.
enum class ListenerAddress : u8 {
    IPv4Wildcard = 0,
    IPv4Exact = 1,
};

inline bool listener_address_valid(ListenerAddress address, u32 ipv4_host) {
    switch (address) {
        case ListenerAddress::IPv4Wildcard:
            return ipv4_host == 0u;
        case ListenerAddress::IPv4Exact:
            return ipv4_host != 0u;
    }
    return false;
}

}  // namespace rut
