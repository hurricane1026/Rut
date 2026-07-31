#include "rut/common/shard_limits.h"
#include "rut/runtime/epoll_event_loop.h"
#include "rut/runtime/iouring_event_loop.h"
#include "rut/runtime/shard.h"
#include "rut/runtime/socket.h"
#include "rut/runtime/tls.h"

#ifdef RUT_ENABLE_JIT
#include "rut/reload_coordinator.h"
#include "rut/serve_loader.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <netinet/in.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

using namespace rut;

// kMaxShards moved to rut/common/shard_limits.h (shared with the
// compiler front-end, which validates `shard:` selectors against it).
static constexpr u32 kDefaultDrainSecs = 30;
static constexpr u16 kDefaultPort = 8080;

struct ServerReloadConfig {
#ifdef RUT_ENABLE_JIT
    const char* source_path = nullptr;
    jit::OptLevel opt = jit::OptLevel::O2;
    LoadedProgram* active = nullptr;
    LoadedProgram* spare = nullptr;
#endif
};

// Status messages go to stderr to avoid mixing with structured JSON access logs on stdout.
static void write_str(const char* s) {
    u32 len = 0;
    while (s[len]) len++;
    (void)write(2, s, len);
}

static void write_u32(u32 val) {
    char buf[12];
    i32 n = 0;
    u32 tmp = val;
    do {
        buf[n++] = static_cast<char>('0' + tmp % 10);
        tmp /= 10;
    } while (tmp);
    for (i32 i = n - 1; i >= 0; i--) (void)write(2, &buf[i], 1);
}

#ifdef RUT_ENABLE_JIT
static void write_u64(u64 val) {
    char buf[24];
    i32 n = 0;
    do {
        buf[n++] = static_cast<char>('0' + val % 10);
        val /= 10;
    } while (val);
    for (i32 i = n - 1; i >= 0; i--) (void)write(2, &buf[i], 1);
}

static void write_reload_record(const ReloadTerminalRecord& record) {
    if (!record.valid) return;
    const char* source = record.source == ReloadRequestSource::Signal ? "signal" : "route";
    const char* outcome = reload_terminal_outcome_name(record.outcome);
    write_str("{\"event\":\"reload\",\"request_id\":");
    write_u64(record.request_id);
    write_str(",\"source\":\"");
    write_str(source);
    write_str("\",\"old_generation\":");
    write_u64(record.old_generation);
    write_str(",\"new_generation\":");
    write_u64(record.new_generation);
    write_str(",\"outcome\":\"");
    write_str(outcome);
    write_str("\"}\n");
}
#endif

static bool str_eq(const char* a, const char* b) {
    while (*a && *b) {
        if (*a != *b) return false;
        a++;
        b++;
    }
    return *a == *b;
}

static bool starts_with_dash_dash(const char* s) {
    return s[0] != '\0' && s[0] == '-' && s[1] == '-';
}

// True only when the whole token is digits — so a numeric-looking path
// like "404.rut" is treated as a program path, not a port.
static bool is_all_digits(const char* s) {
    if (!s || !*s) return false;
    for (const char* p = s; *p; p++) {
        if (*p < '0' || *p > '9') return false;
    }
    return true;
}

static bool detect_io_uring() {
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));
    i32 fd = static_cast<i32>(syscall(__NR_io_uring_setup, 1, &params));
    if (fd >= 0) {
        close(fd);
        return true;
    }
    return false;
}

// --- Signal handling for graceful shutdown ---

static void write_error(const char* prefix, const rut::Error& err) {
    write_str(prefix);
    write_str(" (errno=");
    write_u32(static_cast<u32>(err.code));
    write_str(", source=");
    write_u32(static_cast<u32>(err.source));
    write_str(")\n");
}

template <typename EventLoopType>
static i32 run_shards(u16 port,
                      u32 shard_count,
                      bool pin_cpus,
                      u32 drain_secs,
                      u32 pool_prealloc,
                      TlsServerContext* tls_server,
                      const char* access_log_path,
                      bool access_log_compress,
                      i32 access_log_level,
                      RouteConfig* route_config,
                      bool serve_metrics,
                      ServerReloadConfig* reload_config) {
    Shard<EventLoopType> shards[kMaxShards];
    // Cross-shard metrics registry for snapshots and the optional built-in
    // /metrics endpoint. It outlives the shard threads, which join before this
    // function returns.
    ShardMetrics* metrics_ptrs[kMaxShards];

    // One process-shared limiter backing @rateLimit(scope: global). Lives for the
    // whole server run (run_shards joins all shard threads before returning), so
    // a stack local outlives every shard that points at it.
    static GlobalRateLimiter global_rl;
    global_rl.reset();
    // One process-shared per-upstream concurrency gauge (max-inflight limiting).
    static UpstreamConcurrency upstream_cc;
    upstream_cc.reset();
    // One process-shared bounded mutation boundary. Source lowering is still
    // gated, so route admission starts disabled; the follow-up that lowers
    // reload() also owns the explicit CLI authority flag.
    ControlPlaneMutationPort control_plane_mutation;
    control_plane_mutation.reset(
        route_config != nullptr ? route_config->config_generation : 1, false, route_config);

    // Block process-control signals before publishing the listening state or
    // spawning threads. Threads inherit this mask and the control thread owns
    // every signal through sigtimedwait().
    sigset_t wait_set;
    sigemptyset(&wait_set);
    sigaddset(&wait_set, SIGINT);
    sigaddset(&wait_set, SIGTERM);
    sigaddset(&wait_set, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &wait_set, nullptr);

    // Create one SO_REUSEPORT listen socket per shard.
    // If port==0 (ephemeral), create shard 0 first to get the assigned port,
    // then create remaining sockets on that concrete port.
    for (u32 i = 0; i < shard_count; i++) {
        auto lfd_result = create_listen_socket(port);
        // After shard 0, resolve ephemeral port so remaining shards bind the same port.
        if (i == 0 && port == 0 && lfd_result) {
            struct sockaddr_in a;
            socklen_t al = sizeof(a);
            if (getsockname(lfd_result.value(), reinterpret_cast<struct sockaddr*>(&a), &al) < 0) {
                write_str("Failed to resolve ephemeral port\n");
                close(lfd_result.value());
                return 1;
            }
            port = __builtin_bswap16(a.sin_port);
        }
        if (!lfd_result) {
            write_str("Failed to create listen socket for shard ");
            write_u32(i);
            write_error("", lfd_result.error());
            // Cleanup already-initialized shards
            for (u32 j = 0; j < i; j++) {
                shards[j].stop();
                shards[j].join();
                shards[j].shutdown();
            }
            return 1;
        }
        i32 lfd = lfd_result.value();
        shards[i].owns_listen_fd = true;

        auto rc = shards[i].init(i, lfd, pool_prealloc);
        if (!rc) {
            write_str("Failed to init shard ");
            write_u32(i);
            write_error("", rc.error());
            close(lfd);
            for (u32 j = 0; j < i; j++) {
                shards[j].stop();
                shards[j].join();
                shards[j].shutdown();
            }
            return 1;
        }
        if constexpr (requires { shards[i].loop->tls_server; }) {
            shards[i].loop->tls_server = tls_server;
        }
        // Point every shard at the one shared limiter for @rateLimit(scope: global).
        if constexpr (requires { shards[i].loop->global_rl; }) {
            shards[i].loop->global_rl = &global_rl;
        }
        // …and at the one shared per-upstream concurrency gauge.
        if constexpr (requires { shards[i].loop->upstream_cc; }) {
            shards[i].loop->upstream_cc = &upstream_cc;
        }
        if constexpr (requires { shards[i].loop->control_plane_mutation; }) {
            shards[i].loop->control_plane_mutation = &control_plane_mutation;
        }

        // Hand the compiled routes to the shard. Read-only and shared by
        // every shard (share-nothing applies to mutable per-request
        // state, not the immutable config). spawn() seeds active_config
        // from this pointer. A null config keeps the legacy route-less
        // behavior (every request falls through to the default action).
        shards[i].route_config = route_config;
    }

#ifdef RUT_ENABLE_JIT
    ProcessReloadCoordinator reload_coordinator;
    bool reload_enabled = false;
    if (reload_config != nullptr && reload_config->source_path != nullptr &&
        reload_config->active != nullptr && reload_config->spare != nullptr) {
        ReloadShardEndpoint endpoints[kMaxShards];
        for (u32 i = 0; i < shard_count; i++) endpoints[i].control = &shards[i].control;
        reload_enabled = reload_coordinator.init(&control_plane_mutation,
                                                 reload_config->source_path,
                                                 reload_config->opt,
                                                 reload_config->active,
                                                 reload_config->spare,
                                                 endpoints,
                                                 shard_count);
        if (!reload_enabled) {
            write_str("Failed to initialize reload coordinator\n");
            for (u32 i = 0; i < shard_count; i++) shards[i].shutdown();
            return 1;
        }
    }
#else
    (void)reload_config;
#endif

    // Wire the registry before spawn so stats()/metrics() can latch a bounded
    // process snapshot even when the scrape endpoint is disabled.
    for (u32 i = 0; i < shard_count; i++) metrics_ptrs[i] = &shards[i].shard_metrics;
    for (u32 i = 0; i < shard_count; i++) {
        if constexpr (requires { shards[i].loop->all_shard_metrics; }) {
            shards[i].loop->all_shard_metrics = metrics_ptrs;
            shards[i].loop->shard_metrics_count = shard_count;
            shards[i].loop->metrics_endpoint_enabled = serve_metrics;
        }
    }
    if (serve_metrics) {
        write_str("Metrics: built-in GET /metrics enabled (reserved path — shadows user routes)\n");
    }

    // Get actual port from first shard's socket
    struct sockaddr_in bound_addr;
    socklen_t addr_len = sizeof(bound_addr);
    if (getsockname(
            shards[0].listen_fd, reinterpret_cast<struct sockaddr*>(&bound_addr), &addr_len) < 0) {
        write_str("Failed to get bound address\n");
        for (u32 j = 0; j < shard_count; j++) shards[j].shutdown();
        return 1;
    }
    port = __builtin_bswap16(bound_addr.sin_port);

    // Set up access log flusher if --access-log was specified.
    AccessLogFlusher log_flusher;
    i32 access_log_fd = -1;
    if (access_log_path) {
        access_log_fd = open(access_log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (access_log_fd < 0) {
            write_str("Failed to open access log: ");
            write_str(access_log_path);
            write_str("\n");
            for (u32 j = 0; j < shard_count; j++) shards[j].shutdown();
            return 1;
        }
        // Allocate per-shard access log rings.
        for (u32 i = 0; i < shard_count; i++) {
            auto rc = shards[i].init_access_log();
            if (!rc) {
                write_str("Failed to init access log ring for shard ");
                write_u32(i);
                write_error("", rc.error());
                close(access_log_fd);
                for (u32 j = 0; j < shard_count; j++) shards[j].shutdown();
                return 1;
            }
        }
        log_flusher.init(access_log_fd, access_log_compress, access_log_level);
        for (u32 i = 0; i < shard_count; i++) {
            log_flusher.add_ring(shards[i].log_ring);
        }
    }

    write_str("Listening on port ");
    write_u32(port);
    write_str(" with ");
    write_u32(shard_count);
    write_str(" shard(s)\n");

    // Spawn shard threads
    for (u32 i = 0; i < shard_count; i++) {
        i32 pin = pin_cpus ? static_cast<i32>(i) : -1;
        auto rc = shards[i].spawn(pin);
        if (!rc) {
            write_str("Failed to spawn shard ");
            write_u32(i);
            write_error("", rc.error());
            // Stop all already-spawned shards
            for (u32 j = 0; j < i; j++) shards[j].stop();
            for (u32 j = 0; j < i; j++) shards[j].join();
            for (u32 j = 0; j < shard_count; j++) shards[j].shutdown();
            return 1;
        }
    }

    // Start access log background flusher (if configured).
    if (access_log_fd >= 0) {
        auto flusher_rc = log_flusher.start();
        if (!flusher_rc) {
            write_error("Failed to start access log flusher", flusher_rc.error());
            for (u32 i = 0; i < shard_count; i++) shards[i].stop();
            for (u32 i = 0; i < shard_count; i++) shards[i].join();
            for (u32 i = 0; i < shard_count; i++) shards[i].shutdown();
            close(access_log_fd);
            return 1;
        }
    }

    // Poll reload admission while waiting for shutdown. SIGHUP enters the same
    // single-slot mutation boundary as route-triggered requests; compilation
    // stays on this process-control thread, never a shard thread.
    for (;;) {
        const struct timespec kTimeout{0, 100L * 1000L * 1000L};
        const i32 sig = sigtimedwait(&wait_set, nullptr, &kTimeout);
        if (sig == SIGINT || sig == SIGTERM) break;
#ifdef RUT_ENABLE_JIT
        if (sig == SIGHUP) {
            if (!reload_enabled) {
                write_str("SIGHUP ignored: no .rut program is loaded\n");
            } else if (!reload_coordinator.request_signal()) {
                write_str("Reload request ignored: another reload is pending\n");
                write_reload_record(control_plane_mutation.last_record());
            }
        }
        if (reload_enabled) {
            const ReloadCoordinatorPoll result = reload_coordinator.poll();
            if (result == ReloadCoordinatorPoll::CompileFailed) {
                char msg[512];
                format_load_error(reload_coordinator.last_load_error(), msg, sizeof(msg));
                write_str("Reload failed: ");
                write_str(msg);
                write_str("\n");
                write_reload_record(control_plane_mutation.last_record());
            } else if (result == ReloadCoordinatorPoll::ValidationFailed) {
                write_str("Reload rejected: program is incompatible with the running process\n");
                write_reload_record(control_plane_mutation.last_record());
            } else if (result == ReloadCoordinatorPoll::Published) {
                write_str("Reload published; waiting for shard acknowledgements and old users\n");
            } else if (result == ReloadCoordinatorPoll::Activated) {
                write_str("Reload activated\n");
                write_reload_record(control_plane_mutation.last_record());
            }
        }
#endif
        if (sig < 0 && errno != EAGAIN && errno != EINTR) {
            write_str("sigtimedwait failed; beginning shutdown\n");
            break;
        }
    }

    write_str("Draining connections (");
    write_u32(drain_secs);
    write_str("s)...\n");

    // Begin graceful drain on all shards.
    // Each shard will: respond with Connection: close on new requests,
    // probabilistically close idle connections, and exit when empty or
    // when the drain deadline is reached.
    for (u32 i = 0; i < shard_count; i++) shards[i].drain(drain_secs);

    // Wait for all shard threads to finish (they exit after drain completes).
    for (u32 i = 0; i < shard_count; i++) shards[i].join();

#ifdef RUT_ENABLE_JIT
    // Joining proves there are no remaining request/stream/session pins. Give a
    // published generation one final chance to retire cleanly before stopping
    // the mutation port; process teardown remains safe even if a shard exited
    // before consuming its pending pointer.
    if (reload_enabled) {
        const ReloadCoordinatorPoll kFinalReload = reload_coordinator.poll();
        if (kFinalReload == ReloadCoordinatorPoll::Activated) {
            write_str("Reload activated during shutdown\n");
            write_reload_record(control_plane_mutation.last_record());
        }
    }
#endif
    control_plane_mutation.stop();

    // Stop access log flusher (final flush of remaining entries).
    if (access_log_fd >= 0) {
        log_flusher.stop();
        close(access_log_fd);
    }

    // Release resources.
    for (u32 i = 0; i < shard_count; i++) shards[i].shutdown();

    write_str("Shutdown complete.\n");
    return 0;
}

int main(int argc, char** argv) {
    u16 port = kDefaultPort;
    u32 shard_count = 0;  // 0 = auto-detect
    bool pin_cpus = true;
    u32 drain_secs = kDefaultDrainSecs;
    u32 pool_prealloc = 0;  // 0 = fully lazy
    const char* tls_cert_path = nullptr;
    const char* tls_key_path = nullptr;
    const char* config_path = nullptr;
    const char* access_log_path = nullptr;
    bool access_log_compress = false;
    // Advertise HTTP/2 over ALPN. Opt-in for now: h2 serves static/return-status
    // routes; JIT-handler and proxy routes answer 503 over h2 (follow-up).
    bool offer_h2 = false;
    // Serve an aggregated Prometheus exposition at GET /metrics on the data
    // listener. Opt-in (internal metrics shouldn't be public by default).
    bool serve_metrics = false;
    i32 access_log_level = AccessLogFlusher::kDefaultLevel;
    u32 opt_level = 2;  // JIT IR optimization level (0=low/fast-start .. 3=high)

    // Simple arg parsing: [port] [--shards N] [--no-pin] [--drain N]
    //                      [--tls-cert PATH] [--tls-key PATH]
    //                      [--access-log PATH] [--access-log-compress]
    //                      [--metrics]
    // --metrics: serve an aggregated Prometheus exposition at GET /metrics.
    //   NOTE: this RESERVES the /metrics path — GET /metrics (and /metrics/,
    //   /metrics?…) is served by the built-in endpoint ahead of route matching,
    //   shadowing any user route on that path. Non-GET methods are unaffected.
    for (int i = 1; i < argc; i++) {
        if (is_all_digits(argv[i])) {
            port = 0;
            for (const char* p = argv[i]; *p >= '0' && *p <= '9'; p++)
                port = port * 10 + static_cast<u16>(*p - '0');
        } else if (argv[i][0] != '-') {
            // A bare positional that isn't a pure number is the .rut program
            // path (e.g. "404.rut"). Flag values are consumed via i++ in the
            // blocks below, so they never reach here.
            config_path = argv[i];
        }
        if (i + 1 < argc) {
            if (str_eq(argv[i], "--shards")) {
                if (argv[i + 1][0] < '0' || argv[i + 1][0] > '9') {
                    write_str("--shards requires a numeric argument\n");
                    return 1;
                }
                i++;
                shard_count = 0;
                for (const char* p = argv[i]; *p >= '0' && *p <= '9'; p++)
                    shard_count = shard_count * 10 + static_cast<u32>(*p - '0');
            } else if (str_eq(argv[i], "--drain")) {
                if (argv[i + 1][0] < '0' || argv[i + 1][0] > '9') {
                    write_str("--drain requires a numeric argument\n");
                    return 1;
                }
                i++;
                drain_secs = 0;
                for (const char* p = argv[i]; *p >= '0' && *p <= '9'; p++)
                    drain_secs = drain_secs * 10 + static_cast<u32>(*p - '0');
            } else if (str_eq(argv[i], "--pool-prealloc")) {
                if (argv[i + 1][0] < '0' || argv[i + 1][0] > '9') {
                    write_str("--pool-prealloc requires a numeric argument\n");
                    return 1;
                }
                i++;
                pool_prealloc = 0;
                for (const char* p = argv[i]; *p >= '0' && *p <= '9'; p++)
                    pool_prealloc = pool_prealloc * 10 + static_cast<u32>(*p - '0');
            } else if (str_eq(argv[i], "--access-log")) {
                if (i + 1 >= argc || starts_with_dash_dash(argv[i + 1])) {
                    write_str("--access-log requires a path argument\n");
                    return 1;
                }
                i++;
                access_log_path = argv[i];
            } else if (str_eq(argv[i], "--tls-cert")) {
                if (i + 1 >= argc || starts_with_dash_dash(argv[i + 1])) {
                    write_str("--tls-cert requires a path argument\n");
                    return 1;
                }
                i++;
                tls_cert_path = argv[i];
            } else if (str_eq(argv[i], "--tls-key")) {
                if (i + 1 >= argc || starts_with_dash_dash(argv[i + 1])) {
                    write_str("--tls-key requires a path argument\n");
                    return 1;
                }
                i++;
                tls_key_path = argv[i];
            } else if (str_eq(argv[i], "--access-log-level")) {
                if (argv[i + 1][0] < '0' || argv[i + 1][0] > '9') {
                    write_str("--access-log-level requires a numeric argument\n");
                    return 1;
                }
                i++;
                access_log_level = 0;
                for (const char* p = argv[i]; *p >= '0' && *p <= '9'; p++)
                    access_log_level = access_log_level * 10 + static_cast<i32>(*p - '0');
            } else if (str_eq(argv[i], "--opt")) {
                if (argv[i + 1][0] < '0' || argv[i + 1][0] > '9') {
                    write_str("--opt requires a numeric argument (0-3)\n");
                    return 1;
                }
                i++;
                opt_level = 0;
                for (const char* p = argv[i]; *p >= '0' && *p <= '9'; p++)
                    opt_level = opt_level * 10 + static_cast<u32>(*p - '0');
                if (opt_level > 3) {
                    write_str("--opt must be between 0 and 3\n");
                    return 1;
                }
            }
        }
        if (str_eq(argv[i], "--no-pin")) pin_cpus = false;
        if (str_eq(argv[i], "--access-log-compress")) access_log_compress = true;
        if (str_eq(argv[i], "--h2")) offer_h2 = true;
        if (str_eq(argv[i], "--metrics")) serve_metrics = true;
        // Catch flags that require a value but appear as the last argument.
        if (i + 1 >= argc) {
            if (str_eq(argv[i], "--shards") || str_eq(argv[i], "--drain") ||
                str_eq(argv[i], "--pool-prealloc") || str_eq(argv[i], "--tls-cert") ||
                str_eq(argv[i], "--tls-key") || str_eq(argv[i], "--access-log") ||
                str_eq(argv[i], "--access-log-level") || str_eq(argv[i], "--opt")) {
                write_str(argv[i]);
                write_str(" requires an argument\n");
                return 1;
            }
        }
    }

    // Environment variable override: RUE_ACCESS_LOG_COMPRESS=1
    // getenv without stdlib — scan environ directly.
    {
        extern char** environ;
        static const char kEnv[] = "RUE_ACCESS_LOG_COMPRESS=1";
        for (char** e = environ; *e; e++) {
            if (str_eq(*e, kEnv)) {
                access_log_compress = true;
                break;
            }
        }
    }

    if (shard_count == 0) shard_count = detect_cpu_count();
    if (shard_count > kMaxShards) shard_count = kMaxShards;

    if ((tls_cert_path && !tls_key_path) || (!tls_cert_path && tls_key_path)) {
        write_str("--tls-cert and --tls-key must be provided together\n");
        return 1;
    }

    TlsServerContext* tls_server = nullptr;
    if (tls_cert_path && tls_key_path) {
        auto tls_result = create_tls_server_context(tls_cert_path, tls_key_path, offer_h2);
        if (!tls_result) {
            write_error("Failed to initialize TLS", tls_result.error());
            return 1;
        }
        tls_server = tls_result.value();
        write_str("TLS: enabled\n");
    }

    // Compile the .rut program (if given) into a RouteConfig the shards
    // serve. The loader owns the JIT code + RIR arena + source mapping
    // for the whole run, so it lives at file scope to outlive every
    // shard and to keep the 1.28 MB RouteConfig off the stack.
    RouteConfig* route_config = nullptr;
    ServerReloadConfig server_reload;
#ifdef RUT_ENABLE_JIT
    static LoadedProgram program;
    static LoadedProgram spare_program;
    if (config_path) {
        jit::OptLevel olvl = jit::OptLevel::O2;
        switch (opt_level) {
            case 0:
                olvl = jit::OptLevel::O0;
                break;
            case 1:
                olvl = jit::OptLevel::O1;
                break;
            case 2:
                olvl = jit::OptLevel::O2;
                break;
            case 3:
                olvl = jit::OptLevel::O3;
                break;
            default:
                olvl = jit::OptLevel::O2;
                break;
        }
        LoadError load_err;
        if (!load_rut_program(config_path, program, load_err, olvl)) {
            char msg[512];
            format_load_error(load_err, msg, sizeof(msg));
            write_str("Failed to load ");
            write_str(config_path);
            write_str(": ");
            write_str(msg);
            write_str("\n");
            program.destroy();
            destroy_tls_server_context(tls_server);
            return 1;
        }
        route_config = &program.config;
        server_reload.source_path = config_path;
        server_reload.opt = olvl;
        server_reload.active = &program;
        server_reload.spare = &spare_program;
        // Loading is side-effect free with respect to live Cache state.
        // This startup installation is the activation boundary (no shard
        // exists yet); live reload must pair the same call with its config
        // swap and RCU lifetime handoff.
        activate_rut_program(program);
        write_str("Loaded program: ");
        write_str(config_path);
        write_str(" (opt O");
        write_u32(opt_level);
        write_str(")\n");
    } else {
        write_str("No .rut program given — serving default routes only.\n");
    }
#else
    (void)opt_level;
    if (config_path) {
        write_str("This build has no JIT (RUT_ENABLE_JIT=OFF); cannot load ");
        write_str(config_path);
        write_str("\n");
        destroy_tls_server_context(tls_server);
        return 1;
    }
#endif

    // Fail fast on a shard-pinned timer that can never fire with this
    // --shards value (selector >= shard_count) instead of serving with a
    // silently dead timer.
    if (route_config != nullptr) {
        const i32 bad = route_config->first_out_of_range_timer_shard(shard_count);
        if (bad >= 0) {
            write_str("Timer '");
            write_str(route_config->timers[bad].name);
            write_str("' pins shard ");
            write_u32(static_cast<u32>(route_config->timers[bad].shard));
            write_str(" but only ");
            write_u32(shard_count);
            write_str(" shard(s) are configured\n");
            return 1;
        }
    }

    i32 rc = 0;
    // io_uring now terminates TLS too (event-loop TlsEngine), so it is preferred
    // whenever available — TLS no longer forces the epoll fallback.
    if (detect_io_uring()) {
        write_str(tls_server ? "Backend: io_uring (TLS)\n" : "Backend: io_uring\n");
        rc = run_shards<IoUringEventLoop>(port,
                                          shard_count,
                                          pin_cpus,
                                          drain_secs,
                                          pool_prealloc,
                                          tls_server,
                                          access_log_path,
                                          access_log_compress,
                                          access_log_level,
                                          route_config,
                                          serve_metrics,
                                          &server_reload);
        if (rc != 0 && tls_server) {
            write_str("Backend: io_uring TLS startup failed; falling back to epoll (TLS)\n");
            rc = run_shards<EpollEventLoop>(port,
                                            shard_count,
                                            pin_cpus,
                                            drain_secs,
                                            pool_prealloc,
                                            tls_server,
                                            access_log_path,
                                            access_log_compress,
                                            access_log_level,
                                            route_config,
                                            serve_metrics,
                                            &server_reload);
        }
    } else {
        write_str(tls_server ? "Backend: epoll (TLS)\n" : "Backend: epoll\n");
        rc = run_shards<EpollEventLoop>(port,
                                        shard_count,
                                        pin_cpus,
                                        drain_secs,
                                        pool_prealloc,
                                        tls_server,
                                        access_log_path,
                                        access_log_compress,
                                        access_log_level,
                                        route_config,
                                        serve_metrics,
                                        &server_reload);
    }
    destroy_tls_server_context(tls_server);
#ifdef RUT_ENABLE_JIT
    // Shards have joined inside run_shards; safe to release JIT code,
    // the RIR arena, and the source mapping.
    program.destroy();
    spare_program.destroy();
#endif
    return rc;
}
