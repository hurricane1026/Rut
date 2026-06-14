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

#include "rut/common/types.h"
#include "rut/runtime/traffic_capture.h"
#include "rut/runtime/traffic_replay.h"
#include "rut/sim/simulate_engine.h"

#include <errno.h>
#include <unistd.h>

using namespace rut;

namespace {

static bool write_all(i32 fd, const char* s, u32 len) {
    u32 pos = 0;
    while (pos < len) {
        const ssize_t n = ::write(fd, s + pos, len - pos);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        pos += static_cast<u32>(n);
    }
    return true;
}

static void write_str(i32 fd, const char* s) {
    u32 len = 0;
    while (s[len]) len++;
    (void)write_all(fd, s, len);
}

static void usage() {
    write_str(2, "Usage: rut-simulate <manifest.txt> <capture.bin>\n");
    write_str(2, "Manifest format:\n");
    write_str(2, "  upstream <id> <name>\n");
    write_str(2, "  route <METHOD|ANY> <pattern> status <code>\n");
    write_str(2, "  route <METHOD|ANY> <pattern> proxy <upstream-id>\n");
    write_str(2, "  pattern is prefix-matched and may include ':param' segments\n");
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        usage();
        return 2;
    }

    sim::Manifest manifest;
    if (!sim::load_manifest(argv[1], manifest)) {
        write_str(2, "Failed to load manifest\n");
        return 1;
    }

    sim::ModuleContext module_ctx{};
    if (!sim::build_module_from_manifest(manifest, module_ctx)) {
        module_ctx.destroy();
        write_str(2, "Failed to build RIR module from manifest\n");
        return 1;
    }

    sim::Engine engine;
    if (!engine.init(module_ctx.module, manifest.upstreams, manifest.upstream_count)) {
        module_ctx.destroy();
        write_str(2, "Failed to initialize simulate engine\n");
        return 1;
    }

    ReplayReader reader;
    if (reader.open(argv[2]) != 0) {
        engine.shutdown();
        module_ctx.destroy();
        write_str(2, "Failed to open capture file\n");
        return 1;
    }

    CaptureEntry entry{};
    char line[512];
    sim::SimulateSummary summary{};
    while (reader.next(entry) == 0) {
        const sim::SimulateResult kResult = sim::simulate_one(engine, entry);
        summary.total++;
        sim::accumulate_summary(summary, kResult.verdict);
        const u32 kLen = sim::format_result(kResult, line, sizeof(line));
        (void)write_all(1, line, kLen);
    }
    const bool kTruncated = reader.entries_read != reader.entry_count();
    sim::finalize_summary(summary, reader);
    if (kTruncated) {
        write_str(2, "Capture file is truncated or unreadable\n");
    }

    char summary_buf[256];
    const u32 kSlen = sim::format_summary(summary, summary_buf, sizeof(summary_buf));
    (void)write_all(1, summary_buf, kSlen);

    reader.close();
    engine.shutdown();
    module_ctx.destroy();
    return (summary.failed == 0 && summary.mismatched == 0 && summary.unsupported == 0) ? 0 : 1;
}
