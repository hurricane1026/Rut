#pragma once

#include "rut/common/types.h"

namespace rut::verify {

// Finite protocol models, not C++ threads: an action is atomic within a shard.
// Shared bits represent events, resource ownership and protocol facts. Actors
// model handlers, peers, completion delivery and cancellation independently.
inline constexpr u32 kMaxActors = 8;
inline constexpr u8 kNoFairness = 255;
inline constexpr u32 kNoIndex = ~u32{0};

struct Actor {
    u16 location_count = 0;
    u16 initial = 0;
    u16 terminal = 0;
};

struct Action {
    u8 actor = 0;
    // Actions in the same group share a weak-fairness obligation. Success
    // and failure of one IO must share a group; fairness must not force failure.
    u8 fairness = kNoFairness;
    u16 from = 0;
    u16 to = 0;
    u64 guard_set = 0;
    u64 guard_clear = 0;
    u64 set = 0;
    u64 clear = 0;
    // Assertions are checked AFTER enabling, not silently used as guards.
    // They express e.g. one resume per wait and no reclaim with IO outstanding.
    u64 assert_set = 0;
    u64 assert_clear = 0;
};

struct Invariant {
    u64 when_set = 0;
    u64 when_clear = 0;
    u64 require_set = 0;
    u64 require_clear = 0;
};

struct Model {
    // Action/invariant arrays are borrowed for the duration of check().
    Actor actors[kMaxActors]{};
    u8 actor_count = 0;
    const Action* actions = nullptr;
    u32 action_count = 0;
    u64 initial_bits = 0;
    u64 weak_fairness = 0;
    // All actors terminating while one of these resources is still owned is
    // an error, not a valid terminal state.
    u64 terminal_clear = 0;
    const Invariant* invariants = nullptr;
    u32 invariant_count = 0;
};

struct Limits {
    u32 states = 32768;
    u32 edges = 262144;
    u64 action_checks = 4194304;
};

enum class Issue : u8 {
    None,
    InvalidModel,
    OutOfMemory,
    StateLimit,
    EdgeLimit,
    WorkLimit,
    UnsafeAction,
    InvariantViolation,
    ResourceLeak,
    Deadlock,
    Livelock,
};

struct State {
    u64 bits = 0;
    u16 locations[kMaxActors]{};
};

struct TraceStep {
    u32 action = kNoIndex;
    State state{};  // state AFTER action, or the initial state for kNoIndex
};

struct Result {
    static constexpr u32 kMaxTrace = 128;
    bool ok = false;
    Issue issue = Issue::None;
    u32 state_count = 0;
    u32 edge_count = 0;
    u64 work_count = 0;
    u32 action = kNoIndex;
    u32 invariant = kNoIndex;
    State witness{};
    TraceStep trace[kMaxTrace]{};
    u32 trace_count = 0;
    u32 cycle_start = kNoIndex;
    bool trace_truncated = false;
};

// Exact-state BFS checks every reachable action ordering; iterative SCC
// analysis detects fair infinite executions that never reach global terminal.
// Limits/allocation failures always return ok=false. No hashing collisions or
// search cutoffs are treated as proofs. The trace is owned by the result.
Result check(const Model& model, Limits limits = {});
const char* issue_name(Issue issue);

// Two consecutive waits plus independent completion actors. A losing or
// cancelled operation can drain after the next wait is published. Separate
// generations deliberately prevent old completions from resuming a new wait.
// Each submitted cancel owns an acknowledgement independent of its target;
// reclaim waits for both, in either completion order.
struct WaitProtocolModel {
    static constexpr u32 kMaxActions = 64;
    Model model{};
    Action actions[kMaxActions]{};
    Invariant invariants[8]{};
    u32 win_actions[4]{};
    u32 drain_actions[4]{};
    u32 cancel_ack_actions[4]{};
    u32 reclaim_action = kNoIndex;
    u8 operation_count = 0;

    WaitProtocolModel() = default;
    WaitProtocolModel(const WaitProtocolModel&) = delete;
    WaitProtocolModel& operator=(const WaitProtocolModel&) = delete;
};

// Supports one event or a two-arm race from Rut's six event classes. Unknown
// masks are rejected, not silently abstracted to a supported protocol.
bool build_wait_protocol_model(u8 arms, WaitProtocolModel& out);
bool build_wait_protocol_model(u8 first_arms, u8 second_arms, WaitProtocolModel& out);

}  // namespace rut::verify
