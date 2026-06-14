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

#pragma once

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/access_log.h"
#include "rut/runtime/arena.h"
#include "rut/runtime/error.h"
#include "rut/runtime/event_loop.h"
#include "rut/runtime/metrics.h"
#include "rut/runtime/route_table.h"
#include "rut/runtime/shard_control.h"
#include "rut/runtime/traffic_capture.h"
#include "rut/runtime/upstream_pool.h"

#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/timerfd.h>
#include <unistd.h>

namespace rut {

// Forward declaration (defined below Shard).
inline u32 detect_cpu_count();

// Shard — per-core share-nothing runtime unit.
//
// Each Shard owns:
//   - One EventLoop (mmap'd, ~130MB) with backend, connections, timer wheel
//   - One listen socket (SO_REUSEPORT, kernel distributes across shards)
//   - One Arena (per-request scratch memory, reset between requests)
//   - One OS thread, optionally pinned to a CPU core
//
// Lifecycle: init() → spawn() → [running] → stop() → join() → shutdown()
//
// Thread safety: each Shard is single-threaded. Cross-shard communication
// is lock-free (atomics, per-shard counters). Only stop() is called from
// outside the shard's thread.
//
// Template parameter: EventLoopType — a concrete event loop type such as
// EpollEventLoop, IoUringEventLoop, or the legacy EventLoop<Backend>.

template <typename EventLoopType>
struct Shard {
    static constexpr u32 kScratchArenaSize = 65536;
    u32 id = 0;
    i32 listen_fd = -1;
    bool owns_listen_fd = false;  // if true, close on shutdown

    // EventLoop — mmap'd due to size (~130MB from Connection[16384])
    EventLoopType* loop = nullptr;

    // Per-request scratch arena (reset after each request cycle)
    MmapArena scratch;

    // Upstream connection pool (per-shard, mmap'd due to size)
    UpstreamPool* upstream = nullptr;

    // Per-shard access log ring (mmap'd, read by background flusher thread).
    AccessLogRing* log_ring = nullptr;
    CaptureRing* capture_ring = nullptr;

    // Per-shard metrics (stack-allocated, ~200 bytes).
    ShardMetrics shard_metrics{};

    // Route config — set before spawning threads, read-only during runtime.
    // Phase 3 hot reload will use std::atomic store/load for
    // cross-thread swap + epoch-based reclamation. Currently immutable.
    const RouteConfig* route_config = nullptr;

    // Per-shard control block (control plane → shard thread).
    ShardControlBlock control{};

    // Per-shard RCU epoch (shard thread → control plane reads).
    ShardEpoch epoch{};

    // Active config pointer — updated atomically by poll_command().
    const RouteConfig* active_config = nullptr;

    // Active JIT code pointer — updated atomically by poll_command().
    void* jit_code = nullptr;

    // Thread
    pthread_t thread = 0;
    bool thread_spawned = false;  // true between spawn() and join()

    // Initialize shard: mmap EventLoop, init backend + arena.
    // listen_fd must already be created with SO_REUSEPORT.
    core::Expected<void, Error> init(u32 shard_id, i32 lfd, u32 pool_prealloc = 0) {
        id = shard_id;
        listen_fd = lfd;

        // mmap the EventLoop (too large for stack)
        void* mem = mmap(nullptr,
                         sizeof(EventLoopType),
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS,
                         -1,
                         0);
        if (mem == MAP_FAILED) return core::make_unexpected(Error::from_errno(Error::Source::Mmap));
        loop = new (mem) EventLoopType();

        auto loop_result = loop->init(shard_id, listen_fd, pool_prealloc);
        if (!loop_result) {
            loop->~EventLoopType();
            munmap(loop, sizeof(EventLoopType));
            loop = nullptr;
            return loop_result;
        }

        // Init scratch arena (64KB initial block, grows on demand)
        auto arena_result = scratch.init(kScratchArenaSize);
        if (!arena_result) {
            loop->shutdown();
            loop->~EventLoopType();
            munmap(loop, sizeof(EventLoopType));
            loop = nullptr;
            return arena_result;
        }

        // mmap upstream pool (UpstreamConn[4096] is ~50KB)
        void* up_mem = mmap(nullptr,
                            sizeof(UpstreamPool),
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS,
                            -1,
                            0);
        if (up_mem == MAP_FAILED) {
            scratch.destroy();
            loop->shutdown();
            loop->~EventLoopType();
            munmap(loop, sizeof(EventLoopType));
            loop = nullptr;
            return core::make_unexpected(Error::from_errno(Error::Source::Mmap));
        }
        upstream = new (up_mem) UpstreamPool();
        upstream->init();

        // Access log ring is allocated lazily via init_access_log(),
        // only when --access-log is specified. No ring = no per-request overhead.

        // Init and wire per-shard metrics.
        shard_metrics.init();
        loop->metrics = &shard_metrics;

        // Init per-shard control block and epoch.
        control.pending_config.store(nullptr, std::memory_order_relaxed);
        control.pending_jit.store(nullptr, std::memory_order_relaxed);
        control.pending_capture.store(nullptr, std::memory_order_relaxed);
        epoch.epoch.store(0, std::memory_order_relaxed);

        // Wire control pointers into EventLoop for poll_command/epoch.
        loop->config_ptr = &active_config;
        loop->control = &control;
        loop->epoch = &epoch;
        loop->jit_code_ptr = &jit_code;

        return {};
    }

    // Allocate and wire the per-shard access log ring.
    // Call before spawn(), only when access logging is enabled.
    core::Expected<void, Error> init_access_log() {
        void* ring_mem = mmap(nullptr,
                              sizeof(AccessLogRing),
                              PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS,
                              -1,
                              0);
        if (ring_mem == MAP_FAILED)
            return core::make_unexpected(Error::from_errno(Error::Source::Mmap));
        log_ring = new (ring_mem) AccessLogRing();
        log_ring->init();
        if (loop) loop->access_log = log_ring;
        return {};
    }

    CaptureRing* enable_capture() {
        if (capture_ring) {
            // Ring exists (possibly disabled on loop). Re-apply it.
            if (!thread_spawned) {
                if (loop && !loop->set_capture(capture_ring)) return nullptr;
            } else {
                control.pending_capture.store(capture_ring, std::memory_order_release);
            }
            return capture_ring;
        }
        void* ring_mem = mmap(nullptr,
                              sizeof(CaptureRing),
                              PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS,
                              -1,
                              0);
        if (ring_mem == MAP_FAILED) return nullptr;
        capture_ring = new (ring_mem) CaptureRing();
        capture_ring->init();
        if (!thread_spawned) {
            if (loop && !loop->set_capture(capture_ring)) {
                capture_ring->~CaptureRing();
                munmap(ring_mem, sizeof(CaptureRing));
                capture_ring = nullptr;
                return nullptr;
            }
            return capture_ring;
        }
        control.pending_capture.store(capture_ring, std::memory_order_release);
        return capture_ring;
    }

    void disable_capture() {
        if (!thread_spawned) {
            if (loop) loop->set_capture(nullptr);
            return;
        }
        control.pending_capture.store(kCaptureDisable, std::memory_order_release);
    }

    void free_capture_ring() {
        if (capture_ring) {
            capture_ring->~CaptureRing();
            munmap(capture_ring, sizeof(CaptureRing));
            capture_ring = nullptr;
        }
    }

    // Spawn the shard's thread. Optionally pin to CPU core.
    // pin_cpu: -1 = no pinning, >=0 = pin to that core.
    core::Expected<void, Error> spawn(i32 pin_cpu = -1) {
        if (!loop) return core::make_unexpected(Error::make(EINVAL, Error::Source::Thread));
        // Seed from route_config only if active_config wasn't already set
        // by a reload_config() call before spawn.
        if (!active_config) active_config = route_config;
        if (thread_spawned)
            return core::make_unexpected(Error::make(EEXIST, Error::Source::Thread));

        pthread_attr_t attr;
        i32 attr_rc = pthread_attr_init(&attr);
        if (attr_rc != 0) return core::make_unexpected(Error::make(attr_rc, Error::Source::Thread));

        // Pin to CPU if requested. Use sched_getaffinity to check allowed CPUs
        // (respects cpuset/cgroup restrictions). Fall back to unpinned on failure.
        if (pin_cpu >= 0) {
            cpu_set_t allowed;
            CPU_ZERO(&allowed);
            if (sched_getaffinity(0, sizeof(allowed), &allowed) == 0 &&
                CPU_ISSET(pin_cpu, &allowed)) {
                cpu_set_t cpuset;
                CPU_ZERO(&cpuset);
                CPU_SET(pin_cpu, &cpuset);
                // Best-effort: if setaffinity fails, continue unpinned
                (void)pthread_attr_setaffinity_np(&attr, sizeof(cpuset), &cpuset);
            }
            // If CPU not in allowed set or getaffinity failed, spawn unpinned
        }

        i32 rc = pthread_create(&thread, &attr, thread_entry, this);
        pthread_attr_destroy(&attr);
        if (rc != 0) return core::make_unexpected(Error::make(rc, Error::Source::Thread));
        thread_spawned = true;
        return {};
    }

    // Signal the shard to stop (safe to call from any thread).
    void stop() {
        if (loop) loop->stop();
    }

    // Begin graceful drain (safe to call from any thread).
    // Shard will close idle connections probabilistically over period_secs,
    // respond with Connection: close on new requests, and exit the run loop
    // when all connections are closed or the deadline is reached.
    void drain(u32 period_secs) {
        if (loop) loop->drain(period_secs);
    }

    // Send a config reload to the shard (fire-and-forget).
    // If the shard is running, writes to control block.
    // If stopped/not spawned, applies directly (no thread to race with).
    void reload_config(const RouteConfig* cfg) {
        if (!thread_spawned) {
            // No thread — direct apply.
            active_config = cfg;
            return;
        }
        // Thread may be running or exiting. Queue atomically.
        // If thread consumes it — good. If not, join() applies it.
        control.pending_config.store(cfg, std::memory_order_release);
    }

    // Send a JIT swap to the shard (fire-and-forget).
    void swap_jit(void* code) {
        if (!thread_spawned) {
            jit_code = code;
            return;
        }
        control.pending_jit.store(code, std::memory_order_release);
    }

    // Wait for the shard's thread to finish.
    void join() {
        if (thread_spawned) {
            pthread_join(thread, nullptr);
            thread_spawned = false;
            // Apply any pending updates the thread didn't consume.
            // Thread is guaranteed gone — no race.
            auto* cfg = control.pending_config.exchange(nullptr, std::memory_order_acq_rel);
            if (cfg) active_config = cfg;
            auto* jit = control.pending_jit.exchange(nullptr, std::memory_order_acq_rel);
            if (jit) jit_code = jit;
            auto* cap = control.pending_capture.exchange(nullptr, std::memory_order_acq_rel);
            if (cap == kCaptureDisable) {
                if (loop) loop->set_capture(nullptr);
            } else if (cap) {
                if (loop) loop->set_capture(cap);
            }
        }
    }

    // Release all resources. Stops and joins thread if still running.
    void shutdown() {
        stop();
        join();
        if (log_ring) {
            log_ring->~AccessLogRing();
            munmap(log_ring, sizeof(AccessLogRing));
            log_ring = nullptr;
        }
        free_capture_ring();
        if (upstream) {
            upstream->shutdown();
            upstream->~UpstreamPool();
            munmap(upstream, sizeof(UpstreamPool));
            upstream = nullptr;
        }
        if (loop) {
            // Sync listen_fd: EventLoop may have closed it during drain.
            if (loop->listen_fd < 0) listen_fd = -1;
            loop->access_log = nullptr;
            loop->capture_ring = nullptr;
            loop->shutdown();
            loop->~EventLoopType();
            munmap(loop, sizeof(EventLoopType));
            loop = nullptr;
        }
        scratch.destroy();
        if (owns_listen_fd && listen_fd >= 0) {
            close(listen_fd);
            listen_fd = -1;
        }
    }

private:
    static void* thread_entry(void* arg) {
        auto* self = static_cast<Shard*>(arg);
        self->loop->run();
        return nullptr;
    }

    // No explicit wake — poll_command runs every event loop iteration,
    // and the timerfd fires every 1 second. Perturbing the timerfd to
    // wake the shard immediately would push out the next periodic tick
    // and stall keepalive/drain processing. For admin operations (config
    // reload, JIT swap), up to 1 second latency is acceptable.
};

// Detect CPU count (online cores).
inline u32 detect_cpu_count() {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return (n > 0) ? static_cast<u32>(n) : 1;
}

}  // namespace rut
