#pragma once

#include "rut/common/types.h"

namespace rut {

inline constexpr u32 kMaxHttpTokenListBytes = 4096;
inline constexpr u32 kMaxHttpTokenListItems = 64;

// Validate both complete comma-separated HTTP token lists, then require every
// requested token to occur in allowed. Only SP/HTAB are OWS; no wildcard or
// substring semantics. Empty lists are valid. No allocation or retained views.
bool http_token_list_allows(Str allowed, Str requested, bool case_sensitive);

}  // namespace rut
