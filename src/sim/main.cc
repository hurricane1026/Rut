#include "rut/common/types.h"
#include "rut/platform/write.h"
#include "rut/runtime/traffic_capture.h"
#include "rut/runtime/traffic_replay.h"
#include "rut/sim/simulate_engine.h"

using namespace rut;

namespace {

static void usage() {
    platform::write_diagnostic("Usage: rut-simulate <manifest.txt> <capture.bin>\n");
    platform::write_diagnostic("Manifest format:\n");
    platform::write_diagnostic("  upstream <id> <name>\n");
    platform::write_diagnostic("  route <METHOD|ANY> <pattern> status <code>\n");
    platform::write_diagnostic("  route <METHOD|ANY> <pattern> proxy <upstream-id>\n");
    platform::write_diagnostic("  pattern is prefix-matched and may include ':param' segments\n");
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        usage();
        return 2;
    }

    sim::Manifest manifest;
    if (!sim::load_manifest(argv[1], manifest)) {
        platform::write_diagnostic("Failed to load manifest\n");
        return 1;
    }

    sim::ModuleContext module_ctx{};
    if (!sim::build_module_from_manifest(manifest, module_ctx)) {
        module_ctx.destroy();
        platform::write_diagnostic("Failed to build RIR module from manifest\n");
        return 1;
    }

    sim::Engine engine;
    if (!engine.init(module_ctx.module, manifest.upstreams, manifest.upstream_count)) {
        module_ctx.destroy();
        platform::write_diagnostic("Failed to initialize simulate engine\n");
        return 1;
    }

    ReplayReader reader;
    if (reader.open(argv[2]) != 0) {
        engine.shutdown();
        module_ctx.destroy();
        platform::write_diagnostic("Failed to open capture file\n");
        return 1;
    }

    CaptureEntry entry{};
    char line[512];
    sim::SimulateSummary summary{};
    bool output_ok = true;
    while (output_ok && reader.next(entry) == 0) {
        const sim::SimulateResult kResult = sim::simulate_one(engine, entry);
        summary.total++;
        sim::accumulate_summary(summary, kResult.verdict);
        const u32 kLen = sim::format_result(kResult, line, sizeof(line));
        output_ok = platform::write_all(STDOUT_FILENO, line, kLen);
    }
    if (output_ok) {
        const bool kTruncated = reader.entries_read != reader.entry_count();
        sim::finalize_summary(summary, reader);
        if (kTruncated) platform::write_diagnostic("Capture file is truncated or unreadable\n");

        char summary_buf[256];
        const u32 kSlen = sim::format_summary(summary, summary_buf, sizeof(summary_buf));
        output_ok = platform::write_all(STDOUT_FILENO, summary_buf, kSlen);
    }
    if (!output_ok) platform::write_diagnostic("Failed to write simulation output\n");

    reader.close();
    engine.shutdown();
    module_ctx.destroy();
    return output_ok && summary.failed == 0 && summary.mismatched == 0 && summary.unsupported == 0
               ? 0
               : 1;
}
