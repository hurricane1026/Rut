/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

// Bench JIT-specialized ART vs scalar ART, going through both the
// direct JIT function pointer and the productized RouteConfig::match
// dispatch. The earlier ByteRadix comparison column was retired in
// PR #50 round 5 alongside ByteRadix itself.
//
// Procedure:
//   1. Build a saas-shaped ART trie
//   2. JIT-specialize match() for the trie
//   3. Verify all probes return the same answer between scalar ART
//      and JIT (correctness gate — halt before bench on mismatch)
//   4. Bench: scalar ART, direct-JIT-call, RouteConfig::match-via-JIT
//
// Decision gate (Phase 1 plan): JIT closes -25% saas tax to ≤5%.
// Productized JIT (Phase 2 round 2): ~2.2× faster than scalar ART
// even with method handling + canonicalization in IR.

#include "rut/jit/art_jit_codegen.h"
#include "rut/jit/jit_engine.h"
#include "rut/runtime/route_art.h"
#include "rut/runtime/route_canon.h"
#include "rut/runtime/route_table.h"
#include <chrono>
#include <cstdio>
#include <cstring>

using namespace rut;

namespace {

// SaaS-like routes (subset that fits in a quick spike). Real saas
// has 80+ routes; this 32 is plenty to exercise the descent shape
// (root upgrade to Node16, multi-byte edges, mixed depth).
const char* kRoutes[] = {
    "/api/v1/users",
    "/api/v1/orders",
    "/api/v1/products",
    "/api/v1/sessions",
    "/api/v1/events",
    "/api/v1/teams",
    "/api/v1/projects",
    "/api/v1/messages",
    "/api/v1/channels",
    "/api/v2/users",
    "/api/v2/orders",
    "/admin",
    "/admin/users",
    "/admin/audit",
    "/admin/billing",
    "/oauth/token",
    "/oauth/authorize",
    "/oauth/jwks",
    "/webhooks/stripe",
    "/webhooks/github",
    "/webhooks/slack",
    "/health",
    "/healthz",
    "/metrics",
    "/_status",
    "/_ready",
    "/_live",
    "/internal/debug",
    "/internal/profile",
    "/v1",
    "/v2",
    "/static/css/main.css",
};
constexpr u32 kRouteCount = sizeof(kRoutes) / sizeof(kRoutes[0]);
constexpr u32 kIters = 5'000'000;

double bench_scalar_art(const ArtTrie& art, const char* const* probes, u32 nprobes) {
    volatile u16 sink = 0;
    for (u32 i = 0; i < 50000; i++) {
        const char* p = probes[i % nprobes];
        sink ^= art.match(Str{p, static_cast<u32>(strlen(p))}, 0);
    }
    auto start = std::chrono::high_resolution_clock::now();
    for (u32 i = 0; i < kIters; i++) {
        const char* p = probes[i % nprobes];
        sink ^= art.match(Str{p, static_cast<u32>(strlen(p))}, 0);
    }
    auto end = std::chrono::high_resolution_clock::now();
    (void)sink;
    return std::chrono::duration<double, std::nano>(end - start).count() / kIters;
}

double bench_jit_direct(jit::ArtJitMatchFn fn, const Str* canon_probes, u32 nprobes) {
    // PR #50 round 6: JIT'd fn now expects pre-canonicalized input.
    // Bench pre-canonicalizes outside the timed loop so the
    // measurement reflects pure descent cost.
    volatile u16 sink = 0;
    for (u32 i = 0; i < 50000; i++) {
        const Str& p = canon_probes[i % nprobes];
        sink ^= fn(p.ptr, p.len, 0);
    }
    auto start = std::chrono::high_resolution_clock::now();
    for (u32 i = 0; i < kIters; i++) {
        const Str& p = canon_probes[i % nprobes];
        sink ^= fn(p.ptr, p.len, 0);
    }
    auto end = std::chrono::high_resolution_clock::now();
    (void)sink;
    return std::chrono::duration<double, std::nano>(end - start).count() / kIters;
}

double bench_jit_via_cfg(const RouteConfig& cfg, const char* const* probes, u32 nprobes) {
    volatile u16 sink = 0;
    for (u32 i = 0; i < 50000; i++) {
        const char* p = probes[i % nprobes];
        const RouteEntry* r =
            cfg.match(reinterpret_cast<const u8*>(p), static_cast<u32>(strlen(p)), 0);
        sink ^= reinterpret_cast<uintptr_t>(r);
    }
    auto start = std::chrono::high_resolution_clock::now();
    for (u32 i = 0; i < kIters; i++) {
        const char* p = probes[i % nprobes];
        const RouteEntry* r =
            cfg.match(reinterpret_cast<const u8*>(p), static_cast<u32>(strlen(p)), 0);
        sink ^= reinterpret_cast<uintptr_t>(r);
    }
    auto end = std::chrono::high_resolution_clock::now();
    (void)sink;
    return std::chrono::duration<double, std::nano>(end - start).count() / kIters;
}

// PR #50 round 7 (path A): bench the production hot path. With the HTTP
// parser populating path_canon as a free byproduct of URI scanning, the
// dispatch site calls cfg.match_canonical directly with a pre-canon'd
// view (no canon scan, no strlen). The pre-canonicalization mirrors
// what the parser does once per request — outside the timed loop.
double bench_jit_via_cfg_canonical(const RouteConfig& cfg, const Str* canon_probes, u32 nprobes) {
    volatile u16 sink = 0;
    for (u32 i = 0; i < 50000; i++) {
        const RouteEntry* r = cfg.match_canonical(canon_probes[i % nprobes], 0);
        sink ^= reinterpret_cast<uintptr_t>(r);
    }
    auto start = std::chrono::high_resolution_clock::now();
    for (u32 i = 0; i < kIters; i++) {
        const RouteEntry* r = cfg.match_canonical(canon_probes[i % nprobes], 0);
        sink ^= reinterpret_cast<uintptr_t>(r);
    }
    auto end = std::chrono::high_resolution_clock::now();
    (void)sink;
    return std::chrono::duration<double, std::nano>(end - start).count() / kIters;
}

// Parity check: ArtTrie::match (canonicalizing wrapper) vs JIT'd
// fn called with pre-canonicalized input. Both consume the same
// raw probe; the test harness does the canonicalization for the
// JIT direct-call path the same way RouteConfig::match does.
bool verify_parity(const ArtTrie& art,
                   jit::ArtJitMatchFn jit_fn,
                   const char* const* probes,
                   u32 nprobes) {
    static const u8 kMethods[] = {kRouteMethodAny,
                                  kRouteMethodGet,
                                  kRouteMethodPost,
                                  kRouteMethodPut,
                                  kRouteMethodDelete,
                                  kRouteMethodPatch,
                                  kRouteMethodHead,
                                  kRouteMethodOptions,
                                  kRouteMethodConnect,
                                  kRouteMethodTrace};
    bool ok = true;
    auto check = [&](const char* p) {
        const u32 plen = static_cast<u32>(strlen(p));
        const Str raw{p, plen};
        const bool reject = (plen == 0 || p[0] != '/');
        const Str canon = reject ? Str{nullptr, 0} : canonicalize_request(raw);
        for (u8 m : kMethods) {
            const u16 art_result = art.match(raw, m);
            const u16 jit_result =
                reject ? TrieNode::kInvalidRoute : jit_fn(canon.ptr, canon.len, m);
            if (art_result != jit_result) {
                std::printf("PARITY FAIL on '%s' method=%u: ART=%u, JIT=%u\n",
                            p,
                            m,
                            art_result,
                            jit_result);
                ok = false;
            }
        }
    };
    for (u32 i = 0; i < nprobes; i++) check(probes[i]);
    static const char* kExtraProbes[] = {
        "/admin/anything",
        "/api/v1/users/me",
        "/notregistered",
        "/api/v1/users?q=1",
        "/admin#frag",
        "/admin/",
        "",
        "*",
    };
    for (u32 i = 0; i < sizeof(kExtraProbes) / sizeof(kExtraProbes[0]); i++) {
        check(kExtraProbes[i]);
    }
    return ok;
}

}  // namespace

int main() {
    ArtTrie art;
    for (u32 i = 0; i < kRouteCount; i++) {
        const Str p{kRoutes[i], static_cast<u32>(strlen(kRoutes[i]))};
        art.insert(p, 0, static_cast<u16>(i));
    }
    std::printf("Built ART: %u nodes (n4=%u n16=%u n48=%u n256=%u)\n",
                art.node_count(),
                art.n4_count(),
                art.n16_count(),
                art.n48_count(),
                art.n256_count());

    jit::JitEngine engine;
    if (!engine.init()) {
        std::printf("FAIL: JitEngine::init failed\n");
        return 1;
    }

    auto t0 = std::chrono::high_resolution_clock::now();
    jit::ArtJitMatchFn jit_fn = jit::art_jit_specialize(engine, art, "art_match_phase2");
    auto t1 = std::chrono::high_resolution_clock::now();
    if (!jit_fn) {
        std::printf("FAIL: art_jit_specialize returned null\n");
        engine.shutdown();
        return 1;
    }
    std::printf("JIT codegen + compile: %.2f ms\n",
                std::chrono::duration<double, std::milli>(t1 - t0).count());

    if (!verify_parity(art, jit_fn, kRoutes, kRouteCount)) {
        std::printf("FAIL: parity check failed; aborting bench\n");
        engine.shutdown();
        return 1;
    }
    std::printf("Parity: OK across exact-match + prefix + miss + edge cases (8 methods each)\n");

    // Build a RouteConfig with the JIT'd fn installed.
    RouteConfig cfg;
    // Default kind is ArtJit, no need to call use_art()
    for (u32 i = 0; i < kRouteCount; i++) {
        if (!cfg.add_static(kRoutes[i], 0, 200)) {
            std::printf("FAIL: add_static refused for %s\n", kRoutes[i]);
            engine.shutdown();
            return 1;
        }
    }
    cfg.install_art_jit_fn(jit_fn);

    // Pre-canonicalize once for the direct-JIT bench. Mirrors what
    // RouteConfig::match does once at dispatch entry — measures pure
    // descent cost, not canon scan cost.
    Str canon_probes[kRouteCount];
    for (u32 i = 0; i < kRouteCount; i++) {
        const Str raw{kRoutes[i], static_cast<u32>(strlen(kRoutes[i]))};
        canon_probes[i] = canonicalize_request(raw);
    }

    const double t_scalar = bench_scalar_art(art, kRoutes, kRouteCount);
    const double t_jit_direct = bench_jit_direct(jit_fn, canon_probes, kRouteCount);
    const double t_jit_cfg = bench_jit_via_cfg(cfg, kRoutes, kRouteCount);
    const double t_jit_cfg_canon = bench_jit_via_cfg_canonical(cfg, canon_probes, kRouteCount);

    std::printf("\n=== Latency (ns/match, lower is better) ===\n");
    std::printf("  scalar ART  (ArtTrie::match)         : %7.2f ns\n", t_scalar);
    std::printf("  JIT ART     (direct fn ptr)          : %7.2f ns\n", t_jit_direct);
    std::printf("  JIT ART     (cfg.match, raw input)   : %7.2f ns\n", t_jit_cfg);
    std::printf("  JIT ART     (cfg.match_canonical)    : %7.2f ns  <- prod hot path\n",
                t_jit_cfg_canon);
    std::printf("\n=== JIT speedup vs scalar ART ===\n");
    std::printf("  direct call         : %.2fx\n", t_scalar / t_jit_direct);
    std::printf("  via cfg (raw)       : %.2fx\n", t_scalar / t_jit_cfg);
    std::printf("  via cfg (canonical) : %.2fx\n", t_scalar / t_jit_cfg_canon);

    engine.shutdown();
    return 0;
}
