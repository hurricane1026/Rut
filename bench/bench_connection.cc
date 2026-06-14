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

// Benchmark: Connection alloc/free cycle + memory footprint.
//
// Measures before/after SlicePool integration.
// Build:  ninja -C build bench_connection
// Run:    ./build/bench/bench_connection

#include "bench.h"
#include "rut/runtime/callbacks_impl.h"
#include "rut/runtime/connection.h"
#include "rut/runtime/event_loop.h"
#include "rut/runtime/slice_pool.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

using namespace rut;
using namespace rut::bench;

// Minimal mock backend (just enough for EventLoop to compile).
struct NullBackend {
    static constexpr bool kAsyncIo = false;
    i32 timer_fd = -1;
    core::Expected<void, Error> init(u32, i32) { return {}; }
    void add_accept() {}
    bool add_recv(i32, u32) { return true; }
    bool add_recv_upstream(i32, u32) { return true; }
    bool add_send(i32, u32, const u8*, u32) { return true; }
    bool add_send_upstream(i32, u32, const u8*, u32) { return true; }
    bool add_connect(i32, u32, const void*, u32) { return true; }
    void cancel_accept() {}
    u32 wait(IoEvent*, u32, Connection* = nullptr, u32 = 0) { return 0; }
    void shutdown() {}
};

using NullLoop = EventLoop<NullBackend>;

// Read RSS from /proc/self/statm (Linux-specific, in pages).
static u64 rss_bytes() {
    i32 fd = open("/proc/self/statm", 0);
    if (fd < 0) return 0;
    char buf[128];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    // statm format: "size resident shared text lib data dt"
    // Skip first field (vsize), read second (resident).
    u32 i = 0;
    while (buf[i] && buf[i] != ' ') i++;
    while (buf[i] == ' ') i++;
    u64 pages = 0;
    while (buf[i] >= '0' && buf[i] <= '9') {
        pages = pages * 10 + static_cast<u64>(buf[i] - '0');
        i++;
    }
    return pages * static_cast<u64>(sysconf(_SC_PAGESIZE));
}

int main() {
    Bench b;
    b.title("Connection alloc/free");
    b.min_iterations(500000);
    b.warmup(50000);

    out("sizeof(Connection) = ");
    out_u64(sizeof(Connection));
    out(" bytes\n");
    out("sizeof(EventLoop<NullBackend>) = ");
    out_u64(sizeof(NullLoop));
    out(" bytes\n\n");

    // mmap the EventLoop (too large for stack).
    void* mem =
        mmap(nullptr, sizeof(NullLoop), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        out("mmap failed\n");
        return 1;
    }
    auto* loop = new (mem) NullLoop();
    if (!loop->init(0, -1)) {
        out("init failed\n");
        return 1;
    }

    // Benchmark: alloc + free cycle
    b.run("alloc_free_cycle", [&] {
        Connection* c = loop->alloc_conn();
        if (c) loop->free_conn(*c);
        do_not_optimize(c);
    });

    // Benchmark: alloc 1000, then free all
    b.min_iterations(10000);
    b.warmup(1000);
    b.run("alloc_1000_free_1000", [&] {
        Connection* ptrs[1000];
        u32 n = 0;
        for (u32 i = 0; i < 1000; i++) {
            ptrs[i] = loop->alloc_conn();
            if (ptrs[i]) n++;
        }
        for (u32 i = 0; i < n; i++) loop->free_conn(*ptrs[i]);
        do_not_optimize(&n);
    });

    // Memory footprint: allocate N connections, measure RSS
    out("\n=== Memory footprint ===\n");
    u64 rss_before = rss_bytes();
    constexpr u32 kAllocCount = 10000;
    Connection* conns[kAllocCount];
    u32 alloc_count = 0;
    for (u32 i = 0; i < kAllocCount; i++) {
        conns[i] = loop->alloc_conn();
        if (conns[i]) {
            // Touch the buffers to force page faults
            if (conns[i]->recv_buf.write_avail() > 0) {
                conns[i]->recv_buf.write_ptr()[0] = 0;
                conns[i]->recv_buf.commit(1);
            }
            if (conns[i]->send_buf.write_avail() > 0) {
                conns[i]->send_buf.write_ptr()[0] = 0;
                conns[i]->send_buf.commit(1);
            }
            alloc_count++;
        }
    }
    u64 rss_after = rss_bytes();

    out("  Allocated: ");
    out_u64(alloc_count);
    out(" connections\n");
    out("  RSS before: ");
    out_u64_comma(rss_before / 1024);
    out(" KB\n");
    out("  RSS after:  ");
    out_u64_comma(rss_after / 1024);
    out(" KB\n");
    out("  RSS delta:  ");
    out_u64_comma((rss_after - rss_before) / 1024);
    out(" KB\n");
    out("  Per-conn:   ");
    if (alloc_count > 0) {
        out_u64((rss_after - rss_before) / alloc_count);
    } else {
        out("N/A");
    }
    out(" bytes\n");

    for (u32 i = 0; i < alloc_count; i++) loop->free_conn(*conns[i]);

    loop->~NullLoop();
    munmap(mem, sizeof(NullLoop));
    return 0;
}
