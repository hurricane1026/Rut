#pragma once

#include "rut/common/types.h"

namespace rut {

// Upper bound on per-process shards (one per core). main.cc sizes its shard
// array with this; the compiler front-end validates `timer ..., shard: N`
// selectors against it so a selector that can never match any shard is a
// compile error instead of a silently dead timer.
inline constexpr u32 kMaxShards = 64;

}  // namespace rut
