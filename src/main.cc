#include "rut/common/shard_limits.h"
#include "rut/runtime/access_log_startup.h"
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

#include <errno.h>
#include <fcntl.h>
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

enum class RunShardsOutcomeKind : u8 {
    Success,
    Failure,
    IoUringStartupFailure,
};

struct RunShardsOutcome {
    RunShardsOutcomeKind kind = RunShardsOutcomeKind::Failure;

    i32 exit_code() const { return kind == RunShardsOutcomeKind::Success ? 0 : 1; }
};

static const char* source_live_start_error_name(SourceLiveAccessLogStartErrorKind kind) {
    switch (kind) {
        case SourceLiveAccessLogStartErrorKind::InvalidLifecycle:
            return "InvalidLifecycle";
        case SourceLiveAccessLogStartErrorKind::InvalidOutput:
            return "InvalidOutput";
        case SourceLiveAccessLogStartErrorKind::InvalidRingCount:
            return "InvalidRingCount";
        case SourceLiveAccessLogStartErrorKind::NullRing:
            return "NullRing";
        case SourceLiveAccessLogStartErrorKind::DuplicateRing:
            return "DuplicateRing";
        case SourceLiveAccessLogStartErrorKind::InvalidRingState:
            return "InvalidRingState";
        case SourceLiveAccessLogStartErrorKind::NullLease:
            return "NullLease";
        case SourceLiveAccessLogStartErrorKind::DuplicateLease:
            return "DuplicateLease";
        case SourceLiveAccessLogStartErrorKind::LeaseConflict:
            return "LeaseConflict";
        case SourceLiveAccessLogStartErrorKind::DataEventCreate:
            return "DataEventCreate";
        case SourceLiveAccessLogStartErrorKind::StopEventCreate:
            return "StopEventCreate";
        case SourceLiveAccessLogStartErrorKind::ThreadCreate:
            return "ThreadCreate";
    }
    return "Unknown";
}

static const char* source_live_fatal_name(SourceLiveAccessLogFatalKind kind) {
    switch (kind) {
        case SourceLiveAccessLogFatalKind::None:
            return "None";
        case SourceLiveAccessLogFatalKind::Notify:
            return "Notify";
        case SourceLiveAccessLogFatalKind::Poll:
            return "Poll";
        case SourceLiveAccessLogFatalKind::Write:
            return "Write";
        case SourceLiveAccessLogFatalKind::Protocol:
            return "Protocol";
        case SourceLiveAccessLogFatalKind::RingFull:
            return "RingFull";
    }
    return "Unknown";
}

static void report_source_live_fatal(const SourceLiveAccessLogFatal& fatal) {
    write_str("Fatal SourceLive access log failure (kind=");
    write_str(source_live_fatal_name(fatal.kind));
    write_str(", ring=");
    if (fatal.ring_index == kSourceLiveAccessLogNoRing)
        write_str("none");
    else
        write_u32(fatal.ring_index);
    write_str(", errno=");
    write_u32(static_cast<u32>(fatal.system_error));
    write_str(")\n");
}

static void report_source_live_start_error(const SourceLiveAccessLogStartError& error) {
    write_str("Failed to start SourceLive access log session (kind=");
    write_str(source_live_start_error_name(error.kind));
    write_str(", ring=");
    if (error.ring_index == kSourceLiveAccessLogNoRing)
        write_str("none");
    else
        write_u32(error.ring_index);
    write_str(", errno=");
    write_u32(static_cast<u32>(error.system_error));
    write_str(")\n");
}

template <typename EventLoopType>
static RunShardsOutcome run_shards(ListenerSpec listener,
                                   u32 shard_count,
                                   bool pin_cpus,
                                   u32 drain_secs,
                                   u32 pool_prealloc,
                                   TlsServerContext* tls_server,
                                   const char* access_log_path,
                                   bool access_log_compress,
                                   i32 access_log_level,
                                   SourceAccessLogFd* source_live_fd,
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
            return {RunShardsOutcomeKind::Failure};
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
            const RunShardsOutcomeKind outcome = rc.error().source == Error::Source::IoUring
                                                     ? RunShardsOutcomeKind::IoUringStartupFailure
                                                     : RunShardsOutcomeKind::Failure;
            return {outcome};
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

    if (access_log_path != nullptr && source_live_fd != nullptr) {
        write_str("Conflicting legacy and SourceLive access log modes\n");
        for (u32 j = 0; j < shard_count; j++) shards[j].shutdown();
        return {RunShardsOutcomeKind::Failure};
    }
    if (source_live_fd != nullptr && !*source_live_fd) {
        write_str("Invalid SourceLive access log descriptor\n");
        for (u32 j = 0; j < shard_count; j++) shards[j].shutdown();
        return {RunShardsOutcomeKind::Failure};
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
            return {RunShardsOutcomeKind::Failure};
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
                return {RunShardsOutcomeKind::Failure};
            }
        }
        log_flusher.init(access_log_fd, access_log_compress, access_log_level);
        for (u32 i = 0; i < shard_count; i++) {
            log_flusher.add_ring(shards[i].log_ring);
        }
    }

    SourceLiveAccessLogSession source_live_session;
    SourceLiveAccessLogRingBinding source_live_bindings[kMaxShards]{};
    u32 source_live_ring_count = 0u;
    bool source_live_started = false;
    auto release_source_live_rings = [&]() {
        bool success = true;
        for (u32 i = 0; i < source_live_ring_count; i++) {
            auto released = shards[i].release_live_access_log();
            if (!released) {
                write_str("Failed to release SourceLive access log ring for shard ");
                write_u32(i);
                write_str(" (reason=");
                write_u32(static_cast<u32>(released.error()));
                write_str(")\n");
                success = false;
            }
        }
        source_live_ring_count = 0u;
        return success;
    };
    if (source_live_fd != nullptr) {
        for (u32 i = 0; i < shard_count; i++) {
            auto ring = shards[i].init_live_access_log_ring();
            if (!ring) {
                write_str("Failed to init SourceLive access log ring for shard ");
                write_u32(i);
                write_str(" (reason=");
                write_u32(static_cast<u32>(ring.error()));
                write_str(")\n");
                (void)release_source_live_rings();
                for (u32 j = 0; j < shard_count; j++) shards[j].shutdown();
                return {RunShardsOutcomeKind::Failure};
            }
            source_live_bindings[i] = shards[i].live_access_log_binding();
            source_live_ring_count++;
        }
    }

    // Block SIGINT/SIGTERM so sigwait() can catch them race-free.
    // Must block before spawning threads (threads inherit the mask).
    sigset_t wait_set;
    sigemptyset(&wait_set);
    sigaddset(&wait_set, SIGINT);
    sigaddset(&wait_set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &wait_set, nullptr);

    if (source_live_fd != nullptr) {
        auto started = source_live_session.start(static_cast<SourceAccessLogFd&&>(*source_live_fd),
                                                 source_live_bindings,
                                                 source_live_ring_count);
        if (!started) {
            report_source_live_start_error(started.error());
            (void)release_source_live_rings();
            for (u32 i = 0; i < shard_count; i++) shards[i].shutdown();
            return {RunShardsOutcomeKind::Failure};
        }
        source_live_started = true;
        for (u32 i = 0; i < shard_count; i++) {
            auto attached = shards[i].attach_live_access_log(&source_live_session, i);
            if (!attached) {
                write_str("Failed to attach SourceLive access log producer for shard ");
                write_u32(i);
                write_str(" (reason=");
                write_u32(static_cast<u32>(attached.error()));
                write_str(")\n");
                const SourceLiveAccessLogFinishResult finished = source_live_session.finish();
                source_live_started = false;
                if (finished.status == SourceLiveAccessLogFinishStatus::Fatal)
                    report_source_live_fatal(finished.fatal);
                (void)release_source_live_rings();
                for (u32 j = 0; j < shard_count; j++) shards[j].shutdown();
                return {RunShardsOutcomeKind::Failure};
            }
        }
    }

    bool source_live_fatal_reported = false;
    auto finish_source_live = [&]() {
        bool success = true;
        if (source_live_started) {
            const SourceLiveAccessLogFinishResult finished = source_live_session.finish();
            source_live_started = false;
            if (finished.status != SourceLiveAccessLogFinishStatus::Success) {
                success = false;
                if (finished.status == SourceLiveAccessLogFinishStatus::Fatal &&
                    !source_live_fatal_reported) {
                    report_source_live_fatal(finished.fatal);
                    source_live_fatal_reported = true;
                } else if (finished.status == SourceLiveAccessLogFinishStatus::InvalidLifecycle) {
                    write_str(
                        "Failed to finish SourceLive access log session (invalid lifecycle)\n");
                }
            }
        }
        if (!release_source_live_rings()) success = false;
        return success;
    };

    auto finish_access_logs_and_shutdown = [&]() {
        bool success = true;
        if (access_log_fd >= 0) {
            log_flusher.stop();
            close(access_log_fd);
            access_log_fd = -1;
        }
        if (!finish_source_live()) success = false;
        for (u32 i = 0; i < shard_count; i++) shards[i].shutdown();
        return success;
    };

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
            (void)finish_access_logs_and_shutdown();
            return {RunShardsOutcomeKind::Failure};
        }
    }

    // Start access log background flusher (if configured).
    if (access_log_fd >= 0) {
        auto flusher_rc = log_flusher.start();
        if (!flusher_rc) {
            write_error("Failed to start access log flusher", flusher_rc.error());
            for (u32 i = 0; i < shard_count; i++) shards[i].stop();
            for (u32 i = 0; i < shard_count; i++) shards[i].join();
            (void)finish_access_logs_and_shutdown();
            return {RunShardsOutcomeKind::Failure};
        }
    }

    write_str("Listening on port ");
    write_u32(port);
    write_str(" with ");
    write_u32(shard_count);
    write_str(" shard(s)\n");

    auto stop_all_shards = [&]() {
        for (u32 i = 0; i < shard_count; i++) shards[i].stop();
        for (u32 i = 0; i < shard_count; i++) shards[i].join();
        return finish_access_logs_and_shutdown();
    };

    // Poll for SIGINT/SIGTERM — signals remain blocked and sigtimedwait() is
    // race-free, while the bounded timeout lets the control thread observe a
    // fatal backend error from a shard instead of waiting forever in sigwait().
    i32 sig = 0;
    u32 failed_shard = shard_count;
    i32 backend_error = 0;
    SourceLiveAccessLogFatal source_live_fatal{};
    auto observe_source_live_failure = [&]() {
        if (source_live_fatal.kind != SourceLiveAccessLogFatalKind::None) return true;
        if (!source_live_started) return false;
        source_live_fatal = source_live_session.fatal();
        return source_live_fatal.kind != SourceLiveAccessLogFatalKind::None;
    };
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
    auto report_runtime_failures = [&]() {
        if (source_live_fatal.kind != SourceLiveAccessLogFatalKind::None &&
            !source_live_fatal_reported) {
            report_source_live_fatal(source_live_fatal);
            source_live_fatal_reported = true;
        }
        if (backend_error != 0) report_backend_failure();
    };
    for (;;) {
        struct timespec timeout = {0, 100'000'000};  // 100ms control-plane poll
        sig = sigtimedwait(&wait_set, nullptr, &timeout);
        // A fatal backend state takes precedence over a concurrently queued
        // shutdown signal; otherwise the process could report a graceful exit.
        const bool source_live_failed = observe_source_live_failure();
        const bool backend_failed = observe_backend_failure();
        if (source_live_failed || backend_failed) break;
        if (sig == SIGINT || sig == SIGTERM) break;
        if (sig < 0 && errno != EAGAIN && errno != EINTR) {
            write_str("Failed to wait for shutdown signal\n");
            (void)stop_all_shards();
            return {RunShardsOutcomeKind::Failure};
        }
    }

    if (source_live_fatal.kind != SourceLiveAccessLogFatalKind::None || backend_error != 0) {
        report_runtime_failures();
        (void)stop_all_shards();
        return {RunShardsOutcomeKind::Failure};
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
    const bool source_live_failed_during_drain = observe_source_live_failure();
    const bool backend_failed_during_drain = observe_backend_failure();

    if (source_live_failed_during_drain || backend_failed_during_drain) report_runtime_failures();
    const bool cleanup_succeeded = finish_access_logs_and_shutdown();

    if (source_live_failed_during_drain || backend_failed_during_drain || !cleanup_succeeded) {
        return {RunShardsOutcomeKind::Failure};
    }

    write_str("Shutdown complete.\n");
    return {RunShardsOutcomeKind::Success};
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
    AccessLogSinkSpec source_access_log{};
    const char* access_log_path = nullptr;
    bool cli_access_log_path_present = false;
    bool access_log_compress = false;
    bool cli_access_log_compress_present = false;
    bool environment_access_log_compress_present = false;
    // Advertise HTTP/2 over ALPN. Opt-in for now: h2 serves static/return-status
    // routes; JIT-handler and proxy routes answer 503 over h2 (follow-up).
    bool offer_h2 = false;
    // Serve an aggregated Prometheus exposition at GET /metrics on the data
    // listener. Opt-in (internal metrics shouldn't be public by default).
    bool serve_metrics = false;
    i32 access_log_level = AccessLogFlusher::kDefaultLevel;
    bool cli_access_log_level_present = false;
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
                cli_access_log_path_present = true;
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
                cli_access_log_level_present = true;
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
        if (str_eq(argv[i], "--access-log-compress")) {
            access_log_compress = true;
            cli_access_log_compress_present = true;
        }
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
                environment_access_log_compress_present = true;
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
        source_access_log = program.access_log;
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

    AccessLogStartupInputs access_log_inputs{};
    access_log_inputs.source = source_access_log;
    access_log_inputs.cli_path_present = cli_access_log_path_present;
    access_log_inputs.cli_path = access_log_path;
    access_log_inputs.cli_compression_present = cli_access_log_compress_present;
    access_log_inputs.cli_compression = access_log_compress;
    access_log_inputs.cli_level_present = cli_access_log_level_present;
    access_log_inputs.cli_level = access_log_level;
    access_log_inputs.environment_compression_present = environment_access_log_compress_present;
    auto resolved_access_log = resolve_access_log_startup(access_log_inputs);
    if (!resolved_access_log) {
        switch (resolved_access_log.error()) {
            case AccessLogStartupResolutionError::InvalidSourceSpec:
                write_str("Invalid source accessLog metadata\n");
                break;
            case AccessLogStartupResolutionError::InvalidCliPath:
                write_str("Invalid --access-log path metadata\n");
                break;
            case AccessLogStartupResolutionError::ConflictingCliPath:
                write_str("Conflicting source accessLog and --access-log\n");
                break;
            case AccessLogStartupResolutionError::ConflictingCliCompression:
                write_str("Conflicting source accessLog and --access-log-compress\n");
                break;
            case AccessLogStartupResolutionError::ConflictingCliLevel:
                write_str("Conflicting source accessLog and --access-log-level\n");
                break;
            case AccessLogStartupResolutionError::ConflictingEnvironmentCompression:
                write_str("Conflicting source accessLog and RUE_ACCESS_LOG_COMPRESS=1\n");
                break;
        }
#ifdef RUT_ENABLE_JIT
        program.destroy();
#endif
        destroy_tls_server_context(tls_server);
        return 1;
    }

    SourceAccessLogFd source_live_fd;
    if (resolved_access_log->mode == AccessLogStartupMode::SourceLive) {
        auto source_fd = open_source_access_log(resolved_access_log->source_live);
        if (!source_fd) {
            write_str("Failed to open source accessLog: ");
            write_str(resolved_access_log->source_live.path);
            switch (source_fd.error().kind) {
                case SourceAccessLogOpenErrorKind::InvalidSpec:
                    write_str(" (invalid metadata)");
                    break;
                case SourceAccessLogOpenErrorKind::OpenFailed:
                    write_str(" (open failed, errno=");
                    write_u32(static_cast<u32>(source_fd.error().system_error));
                    write_str(")");
                    break;
                case SourceAccessLogOpenErrorKind::StatFailed:
                    write_str(" (fstat failed, errno=");
                    write_u32(static_cast<u32>(source_fd.error().system_error));
                    write_str(")");
                    break;
                case SourceAccessLogOpenErrorKind::NotRegularFile:
                    write_str(" (target is not a regular file)");
                    break;
            }
            write_str("\n");
#ifdef RUT_ENABLE_JIT
            program.destroy();
#endif
            destroy_tls_server_context(tls_server);
            return 1;
        }
        source_live_fd = static_cast<SourceAccessLogFd&&>(source_fd.value());
    }

    access_log_path = resolved_access_log->mode == AccessLogStartupMode::LegacyCli
                          ? resolved_access_log->legacy_path
                          : nullptr;
    if (resolved_access_log->mode == AccessLogStartupMode::LegacyCli) {
        access_log_compress = resolved_access_log->legacy_compression;
        access_log_level = resolved_access_log->legacy_level;
    }

    const ListenerTransport cli_transport =
        tls_server != nullptr ? ListenerTransport::Tls : ListenerTransport::Cleartext;
    auto resolved_listener = resolve_listener_spec(
        source_listener_present, source_listener, cli_port_present, cli_port, cli_transport);
    if (!resolved_listener) {
        if (resolved_listener.error() == ListenerResolutionError::ConflictingTransport)
            write_str("Conflicting source cleartext listener and CLI TLS\n");
        else if (resolved_listener.error() == ListenerResolutionError::InvalidListenerSpec)
            write_str("Invalid source or CLI listener metadata\n");
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

    RunShardsOutcome outcome{};
    SourceAccessLogFd* source_live_fd_ptr =
        resolved_access_log->mode == AccessLogStartupMode::SourceLive ? &source_live_fd : nullptr;
    // io_uring now terminates TLS too (event-loop TlsEngine), so it is preferred
    // whenever available — TLS no longer forces the epoll fallback.
    if (detect_io_uring()) {
        write_str(tls_server ? "Backend: io_uring (TLS)\n" : "Backend: io_uring\n");
        outcome = run_shards<IoUringEventLoop>(listener,
                                               shard_count,
                                               pin_cpus,
                                               drain_secs,
                                               pool_prealloc,
                                               tls_server,
                                               access_log_path,
                                               access_log_compress,
                                               access_log_level,
                                               source_live_fd_ptr,
                                               route_config,
                                               serve_metrics);
        if (outcome.kind == RunShardsOutcomeKind::IoUringStartupFailure && tls_server) {
            write_str("Backend: io_uring TLS startup failed; falling back to epoll (TLS)\n");
            outcome = run_shards<EpollEventLoop>(listener,
                                                 shard_count,
                                                 pin_cpus,
                                                 drain_secs,
                                                 pool_prealloc,
                                                 tls_server,
                                                 access_log_path,
                                                 access_log_compress,
                                                 access_log_level,
                                                 source_live_fd_ptr,
                                                 route_config,
                                                 serve_metrics);
        }
    } else {
        write_str(tls_server ? "Backend: epoll (TLS)\n" : "Backend: epoll\n");
        outcome = run_shards<EpollEventLoop>(listener,
                                             shard_count,
                                             pin_cpus,
                                             drain_secs,
                                             pool_prealloc,
                                             tls_server,
                                             access_log_path,
                                             access_log_compress,
                                             access_log_level,
                                             source_live_fd_ptr,
                                             route_config,
                                             serve_metrics);
    }
    destroy_tls_server_context(tls_server);
#ifdef RUT_ENABLE_JIT
    // Shards have joined inside run_shards; safe to release JIT code,
    // the RIR arena, and the source mapping.
    program.destroy();
#endif
    return outcome.exit_code();
}
