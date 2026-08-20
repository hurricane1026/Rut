#include "rut/common/shard_limits.h"
#include "rut/runtime/epoll_event_loop.h"
#include "rut/runtime/iouring_event_loop.h"
#include "rut/runtime/listener.h"
#include "rut/runtime/listener_context.h"
#include "rut/runtime/shard.h"
#include "rut/runtime/socket.h"
#include "rut/runtime/tls.h"

#ifdef RUT_ENABLE_JIT
#include "rut/serve_loader.h"
#endif

#include <fcntl.h>
#include <errno.h>
#include <linux/io_uring.h>
#include <netinet/in.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

using namespace rut;

// kMaxShards moved to rut/common/shard_limits.h (shared with the
// compiler front-end, which validates `shard:` selectors against it).
static constexpr u32 kDefaultDrainSecs = 30;

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

static bool parse_cli_port(const char* s, u16& out) {
    if (!is_all_digits(s)) return false;
    u32 value = 0;
    for (const char* p = s; *p; p++) {
        const u32 digit = static_cast<u32>(*p - '0');
        if (value > (65535u - digit) / 10u) return false;
        value = value * 10u + digit;
    }
    out = static_cast<u16>(value);
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
static i32 run_shards(ListenerSpec listener,
                      u32 shard_count,
                      bool pin_cpus,
                      u32 drain_secs,
                      u32 pool_prealloc,
                      TlsServerContext* tls_server,
                      const char* access_log_path,
                      bool access_log_compress,
                      i32 access_log_level,
                      const RouteConfig* route_config,
                      bool serve_metrics) {
    u16 port = listener.port;
    ListenerContext bound_listener_context{};
    Shard<EventLoopType> shards[kMaxShards];
    // Cross-shard metrics registry for the built-in /metrics endpoint. Lives
    // for the whole serve duration (outlives the shard threads, which join
    // before this returns). Only populated under --metrics.
    ShardMetrics* metrics_ptrs[kMaxShards];

    // One process-shared limiter backing @rateLimit(scope: global). Lives for the
    // whole server run (run_shards joins all shard threads before returning), so
    // a stack local outlives every shard that points at it.
    static GlobalRateLimiter global_rl;
    global_rl.reset();
    // One process-shared per-upstream concurrency gauge (max-inflight limiting).
    static UpstreamConcurrency upstream_cc;
    upstream_cc.reset();

    // Create one SO_REUSEPORT listen socket per shard.
    // If port==0 (ephemeral), create shard 0 first to get the assigned port,
    // then create remaining sockets on that concrete port.
    for (u32 i = 0; i < shard_count; i++) {
        ListenerContext derived_context{};
        const ListenerContext* expected_context = i == 0 ? nullptr : &bound_listener_context;
        auto lfd_result = bind_listener_shard(listener, port, expected_context, &derived_context);
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
        if (i == 0) {
            bound_listener_context = derived_context;
            port = bound_listener_context.port;
        }
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
        shards[i].loop->listener_context = bound_listener_context;

        // Hand the compiled routes to the shard. Read-only and shared by
        // every shard (share-nothing applies to mutable per-request
        // state, not the immutable config). spawn() seeds active_config
        // from this pointer. A null config keeps the legacy route-less
        // behavior (every request falls through to the default action).
        shards[i].route_config = route_config;
    }

    // Wire the cross-shard metrics registry so any shard can serve an
    // aggregated GET /metrics. Done after all shards init (loops valid) and
    // before spawn (threads see a fully-built registry).
    if (serve_metrics) {
        for (u32 i = 0; i < shard_count; i++) metrics_ptrs[i] = &shards[i].shard_metrics;
        for (u32 i = 0; i < shard_count; i++) {
            if constexpr (requires { shards[i].loop->all_shard_metrics; }) {
                shards[i].loop->all_shard_metrics = metrics_ptrs;
                shards[i].loop->shard_metrics_count = shard_count;
            }
        }
        write_str("Metrics: built-in GET /metrics enabled (reserved path — shadows user routes)\n");
    }

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

    // Block SIGINT/SIGTERM so sigwait() can catch them race-free.
    // Must block before spawning threads (threads inherit the mask).
    sigset_t wait_set;
    sigemptyset(&wait_set);
    sigaddset(&wait_set, SIGINT);
    sigaddset(&wait_set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &wait_set, nullptr);

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

    auto stop_all_shards = [&]() {
        for (u32 i = 0; i < shard_count; i++) shards[i].stop();
        for (u32 i = 0; i < shard_count; i++) shards[i].join();
        if (access_log_fd >= 0) {
            log_flusher.stop();
            close(access_log_fd);
            access_log_fd = -1;
        }
        for (u32 i = 0; i < shard_count; i++) shards[i].shutdown();
    };

    // Poll for SIGINT/SIGTERM — signals remain blocked and sigtimedwait() is
    // race-free, while the bounded timeout lets the control thread observe a
    // fatal backend error from a shard instead of waiting forever in sigwait().
    i32 sig = 0;
    u32 failed_shard = shard_count;
    i32 backend_error = 0;
    auto observe_backend_failure = [&]() {
        if (backend_error != 0) return true;
        for (u32 i = 0; i < shard_count; i++) {
            const i32 code = shards[i].backend_failure_code();
            if (code != 0) {
                failed_shard = i;
                backend_error = code;
                return true;
            }
        }
        return false;
    };
    auto report_backend_failure = [&]() {
        write_str("Fatal I/O backend failure on shard ");
        write_u32(failed_shard);
        write_str(" (errno=");
        write_u32(static_cast<u32>(backend_error));
        write_str(")\n");
    };
    for (;;) {
        struct timespec timeout = {0, 100'000'000};  // 100ms control-plane poll
        sig = sigtimedwait(&wait_set, nullptr, &timeout);
        // A fatal backend state takes precedence over a concurrently queued
        // shutdown signal; otherwise the process could report a graceful exit.
        if (observe_backend_failure()) break;
        if (sig == SIGINT || sig == SIGTERM) break;
        if (sig < 0 && errno != EAGAIN && errno != EINTR) {
            write_str("Failed to wait for shutdown signal\n");
            stop_all_shards();
            return 1;
        }
    }

    if (backend_error != 0) {
        report_backend_failure();
        stop_all_shards();
        return 1;
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
    const bool backend_failed_during_drain = observe_backend_failure();

    // Stop access log flusher (final flush of remaining entries).
    if (access_log_fd >= 0) {
        log_flusher.stop();
        close(access_log_fd);
    }

    // Release resources.
    for (u32 i = 0; i < shard_count; i++) shards[i].shutdown();

    if (backend_failed_during_drain) {
        report_backend_failure();
        return 1;
    }

    write_str("Shutdown complete.\n");
    return 0;
}

int main(int argc, char** argv) {
    bool cli_port_present = false;
    u16 cli_port = 0;
    u32 shard_count = 0;  // 0 = auto-detect
    bool pin_cpus = true;
    u32 drain_secs = kDefaultDrainSecs;
    u32 pool_prealloc = 0;  // 0 = fully lazy
    const char* tls_cert_path = nullptr;
    const char* tls_key_path = nullptr;
    const char* config_path = nullptr;
    ListenerSpec source_listener{};
    bool source_listener_present = false;
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
            if (!parse_cli_port(argv[i], cli_port)) {
                write_str("CLI listen port must be between 0 and 65535\n");
                return 1;
            }
            cli_port_present = true;
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
    const RouteConfig* route_config = nullptr;
#ifdef RUT_ENABLE_JIT
    static LoadedProgram program;
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
        source_listener_present = program.has_listener;
        if (source_listener_present) source_listener = program.listener;
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

    const ListenerTransport cli_transport =
        tls_server != nullptr ? ListenerTransport::Tls : ListenerTransport::Cleartext;
    auto resolved_listener = resolve_listener_spec(
        source_listener_present, source_listener, cli_port_present, cli_port, cli_transport);
    if (!resolved_listener) {
        if (resolved_listener.error() == ListenerResolutionError::ConflictingTransport)
            write_str("Conflicting source cleartext listener and CLI TLS\n");
        else
            write_str("Conflicting source and CLI listen ports\n");
#ifdef RUT_ENABLE_JIT
        program.destroy();
#endif
        destroy_tls_server_context(tls_server);
        return 1;
    }
    const ListenerSpec listener = resolved_listener.value();
    if ((listener.transport == ListenerTransport::Tls) != (tls_server != nullptr)) {
        write_str("Resolved listener transport does not match CLI TLS settings\n");
#ifdef RUT_ENABLE_JIT
        program.destroy();
#endif
        destroy_tls_server_context(tls_server);
        return 1;
    }
#ifdef RUT_ENABLE_JIT
    if (route_config != nullptr) {
        // Loading is side-effect free with respect to live Cache state. This
        // startup installation is the activation boundary (no shard exists
        // yet); live reload must pair the same call with its config swap and
        // RCU lifetime handoff.
        activate_rut_program(program);
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
        rc = run_shards<IoUringEventLoop>(listener,
                                          shard_count,
                                          pin_cpus,
                                          drain_secs,
                                          pool_prealloc,
                                          tls_server,
                                          access_log_path,
                                          access_log_compress,
                                          access_log_level,
                                          route_config,
                                          serve_metrics);
        if (rc != 0 && tls_server) {
            write_str("Backend: io_uring TLS startup failed; falling back to epoll (TLS)\n");
            rc = run_shards<EpollEventLoop>(listener,
                                            shard_count,
                                            pin_cpus,
                                            drain_secs,
                                            pool_prealloc,
                                            tls_server,
                                            access_log_path,
                                            access_log_compress,
                                            access_log_level,
                                            route_config,
                                            serve_metrics);
        }
    } else {
        write_str(tls_server ? "Backend: epoll (TLS)\n" : "Backend: epoll\n");
        rc = run_shards<EpollEventLoop>(listener,
                                        shard_count,
                                        pin_cpus,
                                        drain_secs,
                                        pool_prealloc,
                                        tls_server,
                                        access_log_path,
                                        access_log_compress,
                                        access_log_level,
                                        route_config,
                                        serve_metrics);
    }
    destroy_tls_server_context(tls_server);
#ifdef RUT_ENABLE_JIT
    // Shards have joined inside run_shards; safe to release JIT code,
    // the RIR arena, and the source mapping.
    program.destroy();
#endif
    return rc;
}
