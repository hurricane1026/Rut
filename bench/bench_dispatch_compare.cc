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

// Dispatch comparison microbench — measures the speedup of ART+JIT
// over linear scan on the same route set, across SIMD ISAs.
//
// PR #50 retired the LinearScan dispatch in round 5 because saas-shape
// data showed ART beating it. This bench reconstructs a fair scalar
// linear-scan reference (memcmp loop, compiler may auto-vectorize at
// -O3) so the headline JIT speedup vs linear can be quoted with
// concrete numbers per architecture.
//
// Strategies measured (lower ns/match is better):
//   1. scalar linear  — memcmp each route, return on first match
//   2. scalar ART     — ArtTrie::match_canonical (current production
//                       fallback when JIT isn't installed)
//   3. JIT ART        — direct call into the LLVM-compiled match fn
//
// Sweep:
//   - route count: 8 / 32 / 128 (= RouteConfig::kMaxRoutes)
//   - URI length distribution: saas-shaped (short to medium)
//   - hit position: first / middle / last / miss — linear scan is
//     position-sensitive (avg case ≈ N/2 comparisons), so we report
//     all four.
//
// SIMD backend: selected at compile time via -DSIMD_ARCH. The CI
// matrix runs scalar/sse2/avx2 + (avx512 when runner has it) + neon.

#include "rut/jit/art_jit_codegen.h"
#include "rut/jit/jit_engine.h"
#include "rut/runtime/route_art.h"
#include "rut/runtime/route_canon.h"
#include <chrono>
#include <cstdio>
#include <cstring>

using namespace rut;

namespace {

// SaaS-like routes — same shape as bench_art_jit_spike.cc but extended
// to 128 entries so we can sweep route-count.
const char* kSaasRoutes[] = {
    "/api/v1/users",
    "/api/v1/orders",
    "/api/v1/products",
    "/api/v1/sessions",
    "/api/v1/events",
    "/api/v1/teams",
    "/api/v1/projects",
    "/api/v1/messages",
    "/api/v1/channels",
    "/api/v1/files",
    "/api/v1/uploads",
    "/api/v1/downloads",
    "/api/v1/permissions",
    "/api/v1/roles",
    "/api/v1/audit",
    "/api/v1/settings",
    "/api/v2/users",
    "/api/v2/orders",
    "/api/v2/products",
    "/api/v2/sessions",
    "/api/v2/events",
    "/api/v2/teams",
    "/api/v2/projects",
    "/api/v2/messages",
    "/api/v2/channels",
    "/api/v2/files",
    "/api/v2/uploads",
    "/api/v2/downloads",
    "/api/v2/permissions",
    "/api/v2/roles",
    "/api/v2/audit",
    "/api/v2/settings",
    "/admin",
    "/admin/users",
    "/admin/audit",
    "/admin/billing",
    "/admin/settings",
    "/admin/permissions",
    "/admin/roles",
    "/admin/quotas",
    "/oauth/token",
    "/oauth/authorize",
    "/oauth/jwks",
    "/oauth/revoke",
    "/oauth/introspect",
    "/oauth/userinfo",
    "/oauth/discovery",
    "/oauth/keys",
    "/webhooks/stripe",
    "/webhooks/github",
    "/webhooks/slack",
    "/webhooks/twilio",
    "/webhooks/segment",
    "/webhooks/intercom",
    "/webhooks/zendesk",
    "/webhooks/hubspot",
    "/health",
    "/healthz",
    "/metrics",
    "/_status",
    "/_ready",
    "/_live",
    "/internal/debug",
    "/internal/profile",
    "/internal/heap",
    "/internal/cpu",
    "/internal/stacks",
    "/internal/config",
    "/internal/version",
    "/internal/build",
    "/v1",
    "/v2",
    "/v3",
    "/v4",
    "/static/css/main.css",
    "/static/js/main.js",
    "/static/img/logo.png",
    "/static/img/favicon.ico",
    "/static/fonts/inter.woff2",
    "/static/fonts/mono.woff2",
    "/api/v1/billing",
    "/api/v1/invoices",
    "/api/v1/subscriptions",
    "/api/v1/customers",
    "/api/v1/refunds",
    "/api/v1/disputes",
    "/api/v1/payouts",
    "/api/v1/balances",
    "/api/v2/billing",
    "/api/v2/invoices",
    "/api/v2/subscriptions",
    "/api/v2/customers",
    "/api/v2/refunds",
    "/api/v2/disputes",
    "/api/v2/payouts",
    "/api/v2/balances",
    "/api/v1/notifications",
    "/api/v1/preferences",
    "/api/v1/integrations",
    "/api/v1/webhooks",
    "/api/v1/api-keys",
    "/api/v1/scim/users",
    "/api/v1/scim/groups",
    "/api/v1/saml",
    "/api/v2/notifications",
    "/api/v2/preferences",
    "/api/v2/integrations",
    "/api/v2/webhooks",
    "/api/v2/api-keys",
    "/api/v2/scim/users",
    "/api/v2/scim/groups",
    "/api/v2/saml",
    "/admin/api-keys",
    "/admin/scim",
    "/admin/saml",
    "/admin/integrations",
    "/admin/webhooks",
    "/admin/audit-log",
    "/admin/quotas/users",
    "/admin/quotas/storage",
    "/admin/quotas/api",
    "/admin/quotas/bandwidth",
    "/admin/regions",
    "/admin/clusters",
    "/admin/keys",
    "/admin/secrets",
    "/admin/policies",
    "/admin/audit/exports",
};
constexpr u32 kMaxRoutes = sizeof(kSaasRoutes) / sizeof(kSaasRoutes[0]);
static_assert(kMaxRoutes == 128, "expected exactly 128 routes");

// Linear-scan reference. Production retired this in round 5 — kept
// here only as a baseline. memcmp is the natural building block;
// modern compilers vectorize it at -O3 for fixed lengths.
struct LinearTable {
    const char* routes[kMaxRoutes];
    u32 lens[kMaxRoutes];
    u32 count;

    void build(u32 n) {
        count = n;
        for (u32 i = 0; i < n; i++) {
            routes[i] = kSaasRoutes[i];
            lens[i] = static_cast<u32>(strlen(kSaasRoutes[i]));
        }
    }

    u16 match(const char* p, u32 plen) const {
        for (u32 i = 0; i < count; i++) {
            if (lens[i] == plen && std::memcmp(routes[i], p, plen) == 0) {
                return static_cast<u16>(i);
            }
        }
        return 0xFFFF;
    }
};

ArtTrie build_art(u32 n) {
    ArtTrie t;
    for (u32 i = 0; i < n; i++) {
        const Str p{kSaasRoutes[i], static_cast<u32>(strlen(kSaasRoutes[i]))};
        t.insert(p, 0, static_cast<u16>(i));
    }
    return t;
}

// Pre-canonicalized probes (raw URI canon'd once outside the timed loop —
// same contract as bench_art_jit_spike's direct-JIT bench).
struct CanonProbes {
    Str canon[kMaxRoutes];
    void build(u32 n) {
        for (u32 i = 0; i < n; i++) {
            const Str raw{kSaasRoutes[i], static_cast<u32>(strlen(kSaasRoutes[i]))};
            canon[i] = canonicalize_request(raw);
        }
    }
};

// Per-strategy bench template — picks `select` index from the route set
// per iteration. Used to vary hit position (first/middle/last/miss).
template <typename Match>
double run_bench(Match match, u32 nprobes, u32 select_kind, u32 iters) {
    // select_kind: 0=first, 1=middle, 2=last, 3=miss
    volatile u32 sink = 0;
    auto pick = [&](u32 i) -> u32 {
        switch (select_kind) {
            case 0:
                return 0;
            case 1:
                return nprobes / 2;
            case 2:
                return nprobes - 1;
            default:
                return nprobes;  // out-of-range → miss
        }
        (void)i;
    };
    // Warmup
    for (u32 i = 0; i < 50000; i++) sink ^= match(pick(i));
    auto start = std::chrono::high_resolution_clock::now();
    for (u32 i = 0; i < iters; i++) sink ^= match(pick(i));
    auto end = std::chrono::high_resolution_clock::now();
    (void)sink;
    return std::chrono::duration<double, std::nano>(end - start).count() / iters;
}

#ifndef BENCH_SIMD_BACKEND
#define BENCH_SIMD_BACKEND "unknown"
#endif

}  // namespace

int main() {
    jit::JitEngine engine;
    if (!engine.init()) {
        std::printf("FAIL: JitEngine::init failed\n");
        return 1;
    }

    constexpr u32 kRouteCounts[] = {8, 32, 128};
    constexpr u32 kIters = 1'000'000;
    constexpr const char* kSelectName[] = {"first", "middle", "last", "miss"};

    std::printf("dispatch comparison — ns per match (lower is better)\n");
    std::printf("Backend: %s\n\n", BENCH_SIMD_BACKEND);

    for (u32 n : kRouteCounts) {
        LinearTable lin;
        lin.build(n);
        ArtTrie art = build_art(n);
        CanonProbes cp;
        cp.build(n);
        char unique_name[64];
        std::snprintf(unique_name, sizeof(unique_name), "art_match_%u", n);
        jit::ArtJitMatchFn jit_fn = jit::art_jit_specialize(engine, art, unique_name);
        if (!jit_fn) {
            std::printf("FAIL: jit_specialize at n=%u\n", n);
            engine.shutdown();
            return 1;
        }

        std::printf("=== %u routes ===\n", n);
        std::printf("%-7s | %12s | %12s | %12s | %s\n",
                    "select",
                    "linear",
                    "scalar ART",
                    "JIT ART",
                    "JIT vs linear");
        std::printf("--------+--------------+--------------+--------------+--------------\n");

        for (u32 sk = 0; sk < 4; sk++) {
            // Linear: feeds raw probe (with leading '/').
            auto m_lin = [&](u32 i) -> u16 {
                const u32 idx = (sk == 3) ? 0 : (sk == 0 ? 0 : (sk == 1 ? n / 2 : n - 1));
                (void)i;
                if (sk == 3) {
                    static const char* miss = "/notregistered";
                    return lin.match(miss, static_cast<u32>(strlen(miss)));
                }
                const char* p = kSaasRoutes[idx];
                return lin.match(p, static_cast<u32>(strlen(p)));
            };
            // Scalar ART: feeds raw probe (canonicalized inside).
            auto m_art = [&](u32 i) -> u16 {
                const u32 idx = (sk == 3) ? 0 : (sk == 0 ? 0 : (sk == 1 ? n / 2 : n - 1));
                (void)i;
                if (sk == 3) {
                    static const char* miss = "/notregistered";
                    return art.match(Str{miss, static_cast<u32>(strlen(miss))}, 0);
                }
                const char* p = kSaasRoutes[idx];
                return art.match(Str{p, static_cast<u32>(strlen(p))}, 0);
            };
            // JIT: feeds canonical probe (pre-canonicalized).
            auto m_jit = [&](u32 i) -> u16 {
                const u32 idx = (sk == 3) ? 0 : (sk == 0 ? 0 : (sk == 1 ? n / 2 : n - 1));
                (void)i;
                if (sk == 3) {
                    static const char* miss_canon = "notregistered";
                    return jit_fn(miss_canon, static_cast<u32>(strlen(miss_canon)), 0);
                }
                const Str& c = cp.canon[idx];
                return jit_fn(c.ptr, c.len, 0);
            };

            const double t_lin = run_bench(m_lin, n, sk, kIters);
            const double t_art = run_bench(m_art, n, sk, kIters);
            const double t_jit = run_bench(m_jit, n, sk, kIters);

            std::printf("%-7s | %9.2f ns | %9.2f ns | %9.2f ns | %8.2fx\n",
                        kSelectName[sk],
                        t_lin,
                        t_art,
                        t_jit,
                        t_lin / t_jit);
        }
        std::printf("\n");
    }

    engine.shutdown();
    return 0;
}
