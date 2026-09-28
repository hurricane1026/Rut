// Canonical segment-prefix dispatch only. Input is emitted by run_matrix.py.
#include "rut/jit/art_jit_codegen.h"
#include "rut/jit/jit_engine.h"
#include "rut/runtime/route_art.h"
#include "rut/runtime/route_select.h"
#include "rut/runtime/route_trie.h"
#include <chrono>
#include <cstdio>
#include <cstring>
using namespace rut;
namespace {
struct Entry {
    char path[512];
    u32 len;
    unsigned method;
    unsigned expected;
};
Entry routes[128], probes[2048];
unsigned order[128], trace[1024];
unsigned count;
bool dynamic_paths;
RouteTrie trie;
ArtTrie art(ArtMatchMode::SegmentPrefix);
jit::ArtJitMatchFn compiled;
bool pattern(const Entry& r, const Entry& p) {
    if (!dynamic_paths)
        return p.len >= r.len && (!r.len || !memcmp(r.path, p.path, r.len)) &&
               (p.len == r.len || !r.len || p.path[r.len] == '/');
    u32 a = 0, b = 0;
    while (a < r.len) {
        if (b >= p.len) return false;
        u32 ae = a, be = b;
        while (ae < r.len && r.path[ae] != '/') ++ae;
        while (be < p.len && p.path[be] != '/') ++be;
        if (r.path[a] != ':' && (ae - a != be - b || memcmp(r.path + a, p.path + b, ae - a)))
            return false;
        a = ae < r.len ? ae + 1 : ae;
        b = be < p.len ? be + 1 : be;
    }
    return true;
}
__attribute__((noinline)) u16 linear(const Entry& p) {
    for (unsigned j = 0; j < count; ++j) {
        unsigned i = order[j];
        const auto& r = routes[i];
        if ((!r.method || r.method == p.method) && pattern(r, p)) return i;
    }
    return 65535;
}
__attribute__((noinline)) u16 scalar(const Entry& p) {
    return art.match_canonical_key({p.path, p.len}, p.method);
}
__attribute__((noinline)) u16 segment(const Entry& p) {
    return trie.match_key({p.path, p.len}, p.method);
}
__attribute__((noinline)) u16 jit_match(const Entry& p) {
    return compiled(p.path, p.len, p.method);
}
using Fn = u16 (*)(const Entry&);
void read_entry(Entry& e) {
    scanf("%u %u %511s", &e.method, &e.expected, e.path);
    if (!strcmp(e.path, "~")) e.path[0] = 0;
    e.len = strlen(e.path);
}
}  // namespace
int main(int argc, char**) {
    char profile[80], name[80];
    unsigned np, nt, params, serial = 0;
    puts("profile,routes,trace,candidate,repeat,ns_per_lookup,checksum");
    while (scanf("%79s %u %u %u %u", profile, &count, &np, &nt, &params) == 5) {
        if (count > 128 || np > 2048) return 2;
        art.clear();
        trie.clear();
        dynamic_paths = params;
        for (unsigned i = 0; i < count; ++i) {
            read_entry(routes[i]);
            if (!trie.insert({routes[i].path, routes[i].len}, routes[i].method, i)) return 3;
            if (!params && !art.insert({routes[i].path, routes[i].len}, routes[i].method, i))
                return 4;
        }
        Str paths[128];
        for (unsigned i = 0; i < count; ++i) paths[i] = {routes[i].path, routes[i].len};
        fprintf(stderr,
                "SELECT %s %u %s\n",
                profile,
                count,
                needs_segment_aware(paths, count) ? "segment_trie" : "jit_art");
        for (unsigned i = 0; i < count; ++i) scanf("%u", order + i);
        for (unsigned i = 0; i < np; ++i) read_entry(probes[i]);
        jit::JitEngine engine;
        if (!params) {
            if (!engine.init()) return 5;
            snprintf(name, sizeof(name), "matrix_%u", serial++);
            compiled = jit::art_jit_specialize(engine, art, name);
            if (!compiled) return 6;
        }
        Fn fns[] = {linear, segment, scalar, jit_match};
        const char* names[] = {"linear", "segment_trie", "scalar_art", "jit_art"};
        unsigned nf = params ? 2 : 4;
        for (unsigned p = 0; p < np; ++p)
            for (unsigned f = 0; f < nf; ++f) {
                auto actual = fns[f](probes[p]);
                if (actual != probes[p].expected) {
                    fprintf(stderr,
                            "FAIL %s %u %s probe=%u %s expected=%u actual=%u\n",
                            profile,
                            count,
                            names[f],
                            p,
                            probes[p].path,
                            probes[p].expected,
                            actual);
                    if (!params) engine.shutdown();
                    return 7;
                }
            }
        for (unsigned t = 0; t < nt; ++t) {
            scanf("%79s", name);
            for (auto& index : trace) scanf("%u", &index);
            for (unsigned rep = 0; rep < (argc > 1 ? 0u : 8u); ++rep)
                for (unsigned offset = 0; offset < nf; ++offset) {
                    unsigned f = (offset + rep) % nf;
                    u64 checksum = 0;
                    for (unsigned i = 0; i < (f == 1 ? 1024u : 8192u); ++i)
                        checksum += fns[f](probes[trace[(i + rep * 128) % 1024]]);
                    auto start = std::chrono::steady_clock::now();
                    for (unsigned i = 0; i < (f == 1 ? 8192u : 131072u); ++i)
                        checksum += fns[f](probes[trace[(i + rep * 128) % 1024]]);
                    auto end = std::chrono::steady_clock::now();
                    double ns = std::chrono::duration<double, std::nano>(end - start).count() /
                                (f == 1 ? 8192 : 131072);
                    printf("%s,%u,%s,%s,%u,%.4f,%llu\n",
                           profile,
                           count,
                           name,
                           names[f],
                           rep,
                           ns,
                           (unsigned long long)checksum);
                }
        }
        if (!params) engine.shutdown();
        fflush(stdout);
    }
}
