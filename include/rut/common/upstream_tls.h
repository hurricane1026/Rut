#pragma once

#include "rut/common/types.h"

namespace rut {
// Owned, pointer-free configuration: safe in native artifacts and RCU snapshots.
struct UpstreamTlsSpec {
    bool enabled = false;
    char ca[256]{};
    char server_name[254]{};
    char cert[256]{};
    char key[256]{};
};
inline bool valid_upstream_tls(const UpstreamTlsSpec& spec) {
    if (!spec.enabled) return true;
    const auto kLiteral = [](const char* value, u32 capacity, bool required) {
        for (u32 i = 0; i < capacity; i++) {
            const u8 kByte = static_cast<u8>(value[i]);
            if (!kByte) return i != 0 || !required;
            if (kByte < 32 || kByte == 127 || kByte == '\\') return false;
        }
        return false;
    };
    if (!kLiteral(spec.ca, sizeof(spec.ca), true) ||
        !kLiteral(spec.server_name, sizeof(spec.server_name), true) ||
        !kLiteral(spec.cert, sizeof(spec.cert), false) ||
        !kLiteral(spec.key, sizeof(spec.key), false) || ((spec.cert[0] != 0) != (spec.key[0] != 0)))
        return false;
    for (u32 i = 0; spec.server_name[i]; i++) {
        const char kChar = spec.server_name[i];
        if (!((kChar >= 'a' && kChar <= 'z') || (kChar >= 'A' && kChar <= 'Z') ||
              (kChar >= '0' && kChar <= '9') || kChar == '.' || kChar == '-'))
            return false;
    }
    return true;
}
}  // namespace rut
