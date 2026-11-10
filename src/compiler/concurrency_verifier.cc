#include "rut/compiler/concurrency_verifier.h"

#include "rut/common/types.h"
#include "rut/runtime/arena.h"

namespace rut::verify {
namespace {

struct Node {
    State state{};
    u32 parent = kNoIndex;
    u32 parent_action = kNoIndex;
    u32 head = kNoIndex;
    u32 index = kNoIndex;
    u32 low = 0;
    u32 component = kNoIndex;
    u64 enabled = 0;
    bool active = false;
    bool terminal = false;
};

struct Edge {
    u32 target = 0;
    u32 action = 0;
    u32 next = kNoIndex;
};

struct Frame {
    u32 node = 0;
    u32 next = kNoIndex;
};

struct Explorer {
    const Model& model;
    Limits limits;
    MmapArena arena{};
    Node* nodes = nullptr;
    Edge* edges = nullptr;
    u32* table = nullptr;
    u32 table_size = 0;
    u32* action_heads = nullptr;
    u32* action_next = nullptr;
    u32 bases[kMaxActors]{};
    u32* stack = nullptr;
    u32* scratch = nullptr;
    u32* path_parent = nullptr;
    u32* path_action = nullptr;
    Frame* frames = nullptr;
    Result result{};

    ~Explorer() { arena.destroy(); }

    bool fail(Issue issue, u32 state = 0, u32 action = kNoIndex) {
        result.issue = issue;
        result.action = action;
        if (nodes && scratch && state < result.state_count) {
            result.witness = nodes[state].state;
            prefix(state);
        }
        return false;
    }

    void append(u32 action, u32 state) {
        if (result.trace_count == Result::kMaxTrace) {
            result.trace_truncated = true;
            return;
        }
        result.trace[result.trace_count++] = {action, nodes[state].state};
    }

    void prefix(u32 state) {
        u32 count = 0;
        for (u32 at = state; at != kNoIndex; at = nodes[at].parent) scratch[count++] = at;
        while (count) {
            const u32 kAt = scratch[--count];
            append(nodes[kAt].parent_action, kAt);
        }
    }

    bool init() {
        if (!model.actor_count || model.actor_count > kMaxActors ||
            (model.action_count && !model.actions) ||
            (model.invariant_count && !model.invariants) || !limits.states ||
            model.action_count > (1u << 20) || model.invariant_count > 1024 ||
            limits.states > (1u << 20) || !limits.edges || limits.edges > (1u << 24))
            return fail(Issue::InvalidModel);
        u32 locations = 0;
        for (u32 a = 0; a < model.actor_count; ++a) {
            const auto& actor = model.actors[a];
            if (!actor.location_count || actor.initial >= actor.location_count ||
                actor.terminal >= actor.location_count)
                return fail(Issue::InvalidModel);
            bases[a] = locations;
            locations += actor.location_count;
        }
        for (u32 i = 0; i < model.action_count; ++i) {
            const auto& action = model.actions[i];
            if (action.actor >= model.actor_count ||
                action.from >= model.actors[action.actor].location_count ||
                action.to >= model.actors[action.actor].location_count ||
                action.from == model.actors[action.actor].terminal ||
                (action.fairness != kNoFairness && action.fairness >= 64) ||
                (action.guard_set & action.guard_clear) || (action.set & action.clear) ||
                (action.assert_set & action.assert_clear))
                return fail(Issue::InvalidModel);
        }
        for (u32 i = 0; i < model.invariant_count; ++i) {
            const auto& invariant = model.invariants[i];
            if ((invariant.when_set & invariant.when_clear) ||
                (invariant.require_set & invariant.require_clear))
                return fail(Issue::InvalidModel);
        }
        if (!arena.init(4096)) return fail(Issue::OutOfMemory);
        table_size = 1;
        while (table_size < limits.states * 2) table_size *= 2;
        nodes = arena.alloc_array<Node>(limits.states);
        edges = arena.alloc_array<Edge>(limits.edges);
        table = arena.alloc_array<u32>(table_size);
        action_heads = arena.alloc_array<u32>(locations);
        action_next = arena.alloc_array<u32>(model.action_count);
        stack = arena.alloc_array<u32>(limits.states);
        scratch = arena.alloc_array<u32>(limits.states);
        path_parent = arena.alloc_array<u32>(limits.states);
        path_action = arena.alloc_array<u32>(limits.states);
        frames = arena.alloc_array<Frame>(limits.states);
        if (!nodes || !edges || !table || !action_heads || (model.action_count && !action_next) ||
            !stack || !scratch || !path_parent || !path_action || !frames)
            return fail(Issue::OutOfMemory);
        for (u32 i = 0; i < locations; ++i) action_heads[i] = kNoIndex;
        // Preserve input order in each location's successor list.
        for (u32 i = model.action_count; i-- > 0;) {
            const auto& action = model.actions[i];
            const u32 kLocation = bases[action.actor] + action.from;
            action_next[i] = action_heads[kLocation];
            action_heads[kLocation] = i;
        }
        return true;
    }

    u64 hash(const State& state) const {
        u64 value = state.bits ^ 0x9e3779b97f4a7c15ull;
        for (u32 a = 0; a < model.actor_count; ++a)
            value = (value ^ state.locations[a]) * 0x100000001b3ull;
        value ^= value >> 33;
        value *= 0xff51afd7ed558ccdull;
        return value ^ (value >> 33);
    }

    bool equal(const State& a, const State& b) const {
        if (a.bits != b.bits) return false;
        for (u32 i = 0; i < model.actor_count; ++i)
            if (a.locations[i] != b.locations[i]) return false;
        return true;
    }

    u32 intern(const State& state, u32 parent, u32 action) {
        u32 bucket = static_cast<u32>(hash(state)) & (table_size - 1);
        while (table[bucket]) {
            const u32 kId = table[bucket] - 1;
            if (equal(nodes[kId].state, state)) return kId;
            bucket = (bucket + 1) & (table_size - 1);
        }
        if (result.state_count == limits.states) return kNoIndex;
        const u32 kId = result.state_count++;
        nodes[kId].state = state;
        nodes[kId].parent = parent;
        nodes[kId].parent_action = action;
        table[bucket] = kId + 1;
        return kId;
    }

    bool explore() {
        State initial{};
        initial.bits = model.initial_bits;
        for (u32 a = 0; a < model.actor_count; ++a) initial.locations[a] = model.actors[a].initial;
        (void)intern(initial, kNoIndex, kNoIndex);
        for (u32 id = 0; id < result.state_count; ++id) {
            Node& node = nodes[id];
            for (u32 i = 0; i < model.invariant_count; ++i) {
                if (result.work_count++ == limits.action_checks) return fail(Issue::WorkLimit, id);
                const auto& invariant = model.invariants[i];
                const u64 kBits = node.state.bits;
                if ((kBits & invariant.when_set) == invariant.when_set &&
                    !(kBits & invariant.when_clear) &&
                    ((kBits & invariant.require_set) != invariant.require_set ||
                     (kBits & invariant.require_clear))) {
                    result.invariant = i;
                    return fail(Issue::InvariantViolation, id);
                }
            }
            bool terminal = true;
            for (u32 a = 0; a < model.actor_count; ++a)
                terminal &= node.state.locations[a] == model.actors[a].terminal;
            if (terminal) {
                if (node.state.bits & model.terminal_clear) return fail(Issue::ResourceLeak, id);
                node.terminal = true;
                continue;
            }
            for (u32 a = 0; a < model.actor_count; ++a) {
                for (u32 i = action_heads[bases[a] + node.state.locations[a]]; i != kNoIndex;
                     i = action_next[i]) {
                    const Action& action = model.actions[i];
                    if (result.work_count++ == limits.action_checks)
                        return fail(Issue::WorkLimit, id, i);
                    if ((node.state.bits & action.guard_set) != action.guard_set ||
                        (node.state.bits & action.guard_clear))
                        continue;
                    if ((node.state.bits & action.assert_set) != action.assert_set ||
                        (node.state.bits & action.assert_clear))
                        return fail(Issue::UnsafeAction, id, i);
                    if (result.edge_count == limits.edges) return fail(Issue::EdgeLimit, id, i);
                    State next = node.state;
                    next.locations[a] = action.to;
                    next.bits = (next.bits & ~action.clear) | action.set;
                    const u32 kTarget = intern(next, id, i);
                    if (kTarget == kNoIndex) return fail(Issue::StateLimit, id, i);
                    Edge& edge = edges[result.edge_count++];
                    edge = {kTarget, i, node.head};
                    node.head = result.edge_count - 1;
                    if (action.fairness != kNoFairness) node.enabled |= u64{1} << action.fairness;
                }
            }
            if (node.head == kNoIndex) return fail(Issue::Deadlock, id);
        }
        return true;
    }

    // Connect two vertices within an SCC, recording an actual executable path.
    void connect(u32 from, u32 to, u32 component) {
        if (from == to) return;
        for (u32 i = 0; i < result.state_count; ++i) path_parent[i] = kNoIndex;
        u32 begin = 0;
        u32 end = 0;
        scratch[end++] = from;
        path_parent[from] = from;
        while (begin < end && path_parent[to] == kNoIndex) {
            const u32 kAt = scratch[begin++];
            for (u32 e = nodes[kAt].head; e != kNoIndex; e = edges[e].next) {
                const u32 kTarget = edges[e].target;
                if (nodes[kTarget].component != component || path_parent[kTarget] != kNoIndex)
                    continue;
                path_parent[kTarget] = kAt;
                path_action[kTarget] = edges[e].action;
                scratch[end++] = kTarget;
            }
        }
        u32 count = 0;
        for (u32 at = to; at != from; at = path_parent[at]) scratch[count++] = at;
        while (count) {
            const u32 kAt = scratch[--count];
            append(path_action[kAt], kAt);
        }
    }

    void cycle_trace(u32 root, u32 component) {
        prefix(root);
        result.cycle_start =
            !result.trace_truncated && result.trace_count ? result.trace_count - 1 : kNoIndex;
        u32 at = root;
        // Include a witness for every fairness group: an internal action or a
        // state where that group is disabled. Touring them yields a fair lasso.
        for (u32 group = 0; group < 64; ++group) {
            if (!(model.weak_fairness & (u64{1} << group))) continue;
            u32 chosen_node = kNoIndex;
            u32 chosen_edge = kNoIndex;
            for (u32 id = 0; id < result.state_count && chosen_edge == kNoIndex; ++id) {
                if (nodes[id].component != component) continue;
                if (!(nodes[id].enabled & (u64{1} << group))) chosen_node = id;
                for (u32 e = nodes[id].head; e != kNoIndex; e = edges[e].next) {
                    if (nodes[edges[e].target].component == component &&
                        model.actions[edges[e].action].fairness == group) {
                        chosen_node = id;
                        chosen_edge = e;
                        break;
                    }
                }
            }
            connect(at, chosen_node, component);
            at = chosen_node;
            if (chosen_edge != kNoIndex) {
                at = edges[chosen_edge].target;
                append(edges[chosen_edge].action, at);
            }
        }
        // Even a cycle with no fairness obligations needs one non-empty step.
        for (u32 e = nodes[at].head; e != kNoIndex; e = edges[e].next) {
            if (nodes[edges[e].target].component != component) continue;
            append(edges[e].action, edges[e].target);
            at = edges[e].target;
            break;
        }
        connect(at, root, component);
    }

    bool liveness() {
        u32 sequence = 0;
        u32 stack_count = 0;
        u32 component = 0;
        for (u32 root = 0; root < result.state_count; ++root) {
            if (nodes[root].terminal || nodes[root].index != kNoIndex) continue;
            u32 depth = 0;
            nodes[root].index = nodes[root].low = sequence++;
            nodes[root].active = true;
            stack[stack_count++] = root;
            frames[depth++] = {root, nodes[root].head};
            while (depth) {
                Frame& frame = frames[depth - 1];
                Node& node = nodes[frame.node];
                if (frame.next != kNoIndex) {
                    const u32 kTarget = edges[frame.next].target;
                    frame.next = edges[frame.next].next;
                    if (nodes[kTarget].terminal) continue;
                    if (nodes[kTarget].index == kNoIndex) {
                        nodes[kTarget].index = nodes[kTarget].low = sequence++;
                        nodes[kTarget].active = true;
                        stack[stack_count++] = kTarget;
                        frames[depth++] = {kTarget, nodes[kTarget].head};
                    } else if (nodes[kTarget].active && nodes[kTarget].index < node.low) {
                        node.low = nodes[kTarget].index;
                    }
                    continue;
                }
                const u32 kId = frame.node;
                --depth;
                if (depth && node.low < nodes[frames[depth - 1].node].low)
                    nodes[frames[depth - 1].node].low = node.low;
                if (node.low != node.index) continue;
                const u32 kOldCount = stack_count;
                u64 always_enabled = model.weak_fairness;
                do {
                    const u32 kMember = stack[--stack_count];
                    nodes[kMember].active = false;
                    nodes[kMember].component = component;
                    always_enabled &= nodes[kMember].enabled;
                } while (stack[stack_count] != kId);
                u64 internal_groups = 0;
                bool cyclic = kOldCount - stack_count > 1;
                for (u32 i = stack_count; i < kOldCount; ++i) {
                    const u32 kMember = stack[i];
                    for (u32 e = nodes[kMember].head; e != kNoIndex; e = edges[e].next) {
                        if (nodes[edges[e].target].component != component) continue;
                        cyclic |= edges[e].target == kMember;
                        const u8 kGroup = model.actions[edges[e].action].fairness;
                        if (kGroup != kNoFairness) internal_groups |= u64{1} << kGroup;
                    }
                }
                if (cyclic && !(always_enabled & ~internal_groups)) {
                    result.issue = Issue::Livelock;
                    result.witness = nodes[kId].state;
                    cycle_trace(kId, component);
                    return false;
                }
                ++component;
            }
        }
        return true;
    }
};

}  // namespace

Result check(const Model& model, Limits limits) {
    Explorer explorer{model, limits};
    if (explorer.init() && explorer.explore() && explorer.liveness()) explorer.result.ok = true;
    return explorer.result;
}

const char* issue_name(Issue issue) {
    switch (issue) {
        case Issue::None:
            return "None";
        case Issue::InvalidModel:
            return "InvalidModel";
        case Issue::OutOfMemory:
            return "OutOfMemory";
        case Issue::StateLimit:
            return "StateLimit";
        case Issue::EdgeLimit:
            return "EdgeLimit";
        case Issue::WorkLimit:
            return "WorkLimit";
        case Issue::UnsafeAction:
            return "UnsafeAction";
        case Issue::InvariantViolation:
            return "InvariantViolation";
        case Issue::ResourceLeak:
            return "ResourceLeak";
        case Issue::Deadlock:
            return "Deadlock";
        case Issue::Livelock:
            return "Livelock";
    }
    return "Unknown";
}

}  // namespace rut::verify
