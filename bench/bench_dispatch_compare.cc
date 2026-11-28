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
static constexpr Str kSaasRoutes[] = {
    lit_str("/api/v1/users"),
    lit_str("/api/v1/orders"),
    lit_str("/api/v1/products"),
    lit_str("/api/v1/sessions"),
    lit_str("/api/v1/events"),
    lit_str("/api/v1/teams"),
    lit_str("/api/v1/projects"),
    lit_str("/api/v1/messages"),
    lit_str("/api/v1/channels"),
    lit_str("/api/v1/files"),
    lit_str("/api/v1/uploads"),
    lit_str("/api/v1/downloads"),
    lit_str("/api/v1/permissions"),
    lit_str("/api/v1/roles"),
    lit_str("/api/v1/audit"),
    lit_str("/api/v1/settings"),
    lit_str("/api/v2/users"),
    lit_str("/api/v2/orders"),
    lit_str("/api/v2/products"),
    lit_str("/api/v2/sessions"),
    lit_str("/api/v2/events"),
    lit_str("/api/v2/teams"),
    lit_str("/api/v2/projects"),
    lit_str("/api/v2/messages"),
    lit_str("/api/v2/channels"),
    lit_str("/api/v2/files"),
    lit_str("/api/v2/uploads"),
    lit_str("/api/v2/downloads"),
    lit_str("/api/v2/permissions"),
    lit_str("/api/v2/roles"),
    lit_str("/api/v2/audit"),
    lit_str("/api/v2/settings"),
    lit_str("/admin"),
    lit_str("/admin/users"),
    lit_str("/admin/audit"),
    lit_str("/admin/billing"),
    lit_str("/admin/settings"),
    lit_str("/admin/permissions"),
    lit_str("/admin/roles"),
    lit_str("/admin/quotas"),
    lit_str("/oauth/token"),
    lit_str("/oauth/authorize"),
    lit_str("/oauth/jwks"),
    lit_str("/oauth/revoke"),
    lit_str("/oauth/introspect"),
    lit_str("/oauth/userinfo"),
    lit_str("/oauth/discovery"),
    lit_str("/oauth/keys"),
    lit_str("/webhooks/stripe"),
    lit_str("/webhooks/github"),
    lit_str("/webhooks/slack"),
    lit_str("/webhooks/twilio"),
    lit_str("/webhooks/segment"),
    lit_str("/webhooks/intercom"),
    lit_str("/webhooks/zendesk"),
    lit_str("/webhooks/hubspot"),
    lit_str("/health"),
    lit_str("/healthz"),
    lit_str("/metrics"),
    lit_str("/_status"),
    lit_str("/_ready"),
    lit_str("/_live"),
    lit_str("/internal/debug"),
    lit_str("/internal/profile"),
    lit_str("/internal/heap"),
    lit_str("/internal/cpu"),
    lit_str("/internal/stacks"),
    lit_str("/internal/config"),
    lit_str("/internal/version"),
    lit_str("/internal/build"),
    lit_str("/v1"),
    lit_str("/v2"),
    lit_str("/v3"),
    lit_str("/v4"),
    lit_str("/static/css/main.css"),
    lit_str("/static/js/main.js"),
    lit_str("/static/img/logo.png"),
    lit_str("/static/img/favicon.ico"),
    lit_str("/static/fonts/inter.woff2"),
    lit_str("/static/fonts/mono.woff2"),
    lit_str("/api/v1/billing"),
    lit_str("/api/v1/invoices"),
    lit_str("/api/v1/subscriptions"),
    lit_str("/api/v1/customers"),
    lit_str("/api/v1/refunds"),
    lit_str("/api/v1/disputes"),
    lit_str("/api/v1/payouts"),
    lit_str("/api/v1/balances"),
    lit_str("/api/v2/billing"),
    lit_str("/api/v2/invoices"),
    lit_str("/api/v2/subscriptions"),
    lit_str("/api/v2/customers"),
    lit_str("/api/v2/refunds"),
    lit_str("/api/v2/disputes"),
    lit_str("/api/v2/payouts"),
    lit_str("/api/v2/balances"),
    lit_str("/api/v1/notifications"),
    lit_str("/api/v1/preferences"),
    lit_str("/api/v1/integrations"),
    lit_str("/api/v1/webhooks"),
    lit_str("/api/v1/api-keys"),
    lit_str("/api/v1/scim/users"),
    lit_str("/api/v1/scim/groups"),
    lit_str("/api/v1/saml"),
    lit_str("/api/v2/notifications"),
    lit_str("/api/v2/preferences"),
    lit_str("/api/v2/integrations"),
    lit_str("/api/v2/webhooks"),
    lit_str("/api/v2/api-keys"),
    lit_str("/api/v2/scim/users"),
    lit_str("/api/v2/scim/groups"),
    lit_str("/api/v2/saml"),
    lit_str("/admin/api-keys"),
    lit_str("/admin/scim"),
    lit_str("/admin/saml"),
    lit_str("/admin/integrations"),
    lit_str("/admin/webhooks"),
    lit_str("/admin/audit-log"),
    lit_str("/admin/quotas/users"),
    lit_str("/admin/quotas/storage"),
    lit_str("/admin/quotas/api"),
    lit_str("/admin/quotas/bandwidth"),
    lit_str("/admin/regions"),
    lit_str("/admin/clusters"),
    lit_str("/admin/keys"),
    lit_str("/admin/secrets"),
    lit_str("/admin/policies"),
    lit_str("/admin/audit/exports"),
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
    static_assert(kMaxRoutes <= UINT16_MAX);

    void build(u32 n) {
        count = n;
        for (u32 i = 0; i < n; i++) {
            routes[i] = kSaasRoutes[i].ptr;
            lens[i] = kSaasRoutes[i].len;
        }
    }

    u16 match(const char* p, u32 plen) const {
        for (u16 i = 0; i < count; i++) {
            if (lens[i] == plen && std::memcmp(routes[i], p, plen) == 0) {
                return i;
            }
        }
        return 0xFFFF;
    }
};

ArtTrie build_art(u32 n) {
    ArtTrie t;
    for (u16 i = 0; i < n; i++) {
        const Str p = kSaasRoutes[i];
        t.insert(p, 0, i);
    }
    return t;
}

// Pre-canonicalized probes (raw URI canon'd once outside the timed loop —
// same contract as bench_art_jit_spike's direct-JIT bench).
struct CanonProbes {
    Str canon[kMaxRoutes];
    void build(u32 n) {
        for (u32 i = 0; i < n; i++) {
            const Str raw = kSaasRoutes[i];
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
    auto pick = [&](u32) -> u32 {
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
    };
    // Warmup
    for (u32 i = 0; i < 50000; i++) sink ^= match(pick(i));
    auto start = std::chrono::high_resolution_clock::now();
    for (u32 i = 0; i < iters; i++) sink ^= match(pick(i));
    auto end = std::chrono::high_resolution_clock::now();
    [[maybe_unused]] const auto result = sink;
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
            auto m_lin = [&](u32) -> u16 {
                const u32 idx = (sk == 3) ? 0 : (sk == 0 ? 0 : (sk == 1 ? n / 2 : n - 1));
                if (sk == 3) {
                    constexpr Str miss = lit_str("/notregistered");
                    return lin.match(miss.ptr, miss.len);
                }
                const Str p = kSaasRoutes[idx];
                return lin.match(p.ptr, p.len);
            };
            // Scalar ART: feeds raw probe (canonicalized inside).
            auto m_art = [&](u32) -> u16 {
                const u32 idx = (sk == 3) ? 0 : (sk == 0 ? 0 : (sk == 1 ? n / 2 : n - 1));
                if (sk == 3) {
                    constexpr Str miss = lit_str("/notregistered");
                    return art.match(miss, 0);
                }
                const Str p = kSaasRoutes[idx];
                return art.match(p, 0);
            };
            // JIT: feeds canonical probe (pre-canonicalized).
            auto m_jit = [&](u32) -> u16 {
                const u32 idx = (sk == 3) ? 0 : (sk == 0 ? 0 : (sk == 1 ? n / 2 : n - 1));
                if (sk == 3) {
                    constexpr Str miss_canon = lit_str("notregistered");
                    return jit_fn(miss_canon.ptr, miss_canon.len, 0);
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
