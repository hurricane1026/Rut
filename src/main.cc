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

#include "rut/runtime/epoll_event_loop.h"
#include "rut/runtime/iouring_event_loop.h"
#include "rut/runtime/shard.h"
#include "rut/runtime/socket.h"
#include "rut/runtime/tls.h"

#include <fcntl.h>
#include <linux/io_uring.h>
#include <netinet/in.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

using namespace rut;

static constexpr u32 kMaxShards = 64;
static constexpr u32 kDefaultDrainSecs = 30;
static constexpr u16 kDefaultPort = 8080;

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
                      i32 access_log_level) {
    Shard<EventLoopType> shards[kMaxShards];

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

    // Wait for SIGINT/SIGTERM — sigwait() is race-free (signal is blocked).
    i32 sig = 0;
    sigwait(&wait_set, &sig);

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
    const char* access_log_path = nullptr;
    bool access_log_compress = false;
    i32 access_log_level = AccessLogFlusher::kDefaultLevel;

    // Simple arg parsing: [port] [--shards N] [--no-pin] [--drain N]
    //                      [--tls-cert PATH] [--tls-key PATH]
    //                      [--access-log PATH] [--access-log-compress]
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] >= '0' && argv[i][0] <= '9') {
            port = 0;
            for (const char* p = argv[i]; *p >= '0' && *p <= '9'; p++)
                port = port * 10 + static_cast<u16>(*p - '0');
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
            }
        }
        if (str_eq(argv[i], "--no-pin")) pin_cpus = false;
        if (str_eq(argv[i], "--access-log-compress")) access_log_compress = true;
        // Catch flags that require a value but appear as the last argument.
        if (i + 1 >= argc) {
            if (str_eq(argv[i], "--shards") || str_eq(argv[i], "--drain") ||
                str_eq(argv[i], "--pool-prealloc") || str_eq(argv[i], "--tls-cert") ||
                str_eq(argv[i], "--tls-key") || str_eq(argv[i], "--access-log") ||
                str_eq(argv[i], "--access-log-level")) {
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
        auto tls_result = create_tls_server_context(tls_cert_path, tls_key_path);
        if (!tls_result) {
            write_error("Failed to initialize TLS", tls_result.error());
            return 1;
        }
        tls_server = tls_result.value();
        write_str("TLS: enabled\n");
    }

    i32 rc = 0;
    if (tls_server) {
        write_str("Backend: epoll (TLS)\n");
        rc = run_shards<EpollEventLoop>(port,
                                        shard_count,
                                        pin_cpus,
                                        drain_secs,
                                        pool_prealloc,
                                        tls_server,
                                        access_log_path,
                                        access_log_compress,
                                        access_log_level);
    } else if (detect_io_uring()) {
        write_str("Backend: io_uring\n");
        rc = run_shards<IoUringEventLoop>(port,
                                          shard_count,
                                          pin_cpus,
                                          drain_secs,
                                          pool_prealloc,
                                          tls_server,
                                          access_log_path,
                                          access_log_compress,
                                          access_log_level);
    } else {
        write_str("Backend: epoll\n");
        rc = run_shards<EpollEventLoop>(port,
                                        shard_count,
                                        pin_cpus,
                                        drain_secs,
                                        pool_prealloc,
                                        tls_server,
                                        access_log_path,
                                        access_log_compress,
                                        access_log_level);
    }
    destroy_tls_server_context(tls_server);
    return rc;
}
