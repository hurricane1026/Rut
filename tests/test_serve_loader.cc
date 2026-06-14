// Tests for the .rut program loader (src/serve_loader.cc): the bridge that
// compiles a source file end to end (lex -> parse -> analyze -> MIR -> RIR ->
// JIT) into a RouteConfig, plus its fail-closed error reporting.

#include "rut/serve_loader.h"
#include "test.h"
#include <filesystem>
#include <fstream>
#include <string>

using namespace rut;

namespace {

// Write `contents` to a fresh file under a unique per-test directory and
// return its path. The directory is created if needed.
std::string write_file(const std::string& dir, const char* name, const char* contents) {
    std::filesystem::create_directories(dir);
    const std::string path = dir + "/" + name;
    std::ofstream out(path, std::ios::binary);
    out << contents;
    out.close();
    return path;
}

bool contains(const char* haystack, const char* needle) {
    return std::string(haystack).find(needle) != std::string::npos;
}

}  // namespace

TEST(serve_loader, status_routes_load) {
    const std::string dir = "/tmp/rut_serve_loader_status";
    const std::string path = write_file(dir,
                                        "app.rut",
                                        "route GET \"/\" { return 200 }\n"
                                        "route GET \"/health\" { return 204 }\n");

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    // Both routes registered into the config the shards will serve.
    CHECK_EQ(program.config.route_count, 2u);
    program.destroy();
}

TEST(serve_loader, missing_file_fails_at_read) {
    LoadedProgram program;
    LoadError err;
    CHECK_FALSE(load_rut_program("/tmp/rut_serve_loader_does_not_exist.rut", program, err));
    CHECK(err.stage == LoadStage::Read);
    CHECK_FALSE(err.has_diag);
    program.destroy();
}

TEST(serve_loader, empty_program_loads_routeless) {
    // Zero-byte file: must load (no null-pointer arithmetic in lex) and
    // produce an empty route table.
    const std::string path = write_file("/tmp/rut_serve_loader_empty", "empty.rut", "");

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    CHECK_EQ(program.config.route_count, 0u);
    program.destroy();
}

TEST(serve_loader, parse_error_reports_stage_and_message) {
    const std::string path =
        write_file("/tmp/rut_serve_loader_parse", "bad.rut", "route GET \"/\" { this is broken\n");

    LoadedProgram program;
    LoadError err;
    CHECK_FALSE(load_rut_program(path.c_str(), program, err));
    CHECK(err.stage == LoadStage::Parse);
    CHECK(err.has_diag);

    char msg[256];
    const u32 n = format_load_error(err, msg, sizeof(msg));
    CHECK_GT(n, 0u);
    CHECK(contains(msg, "parse"));
    CHECK(contains(msg, "failed"));
    program.destroy();
}

TEST(serve_loader, import_resolves_relative_to_program) {
    const std::string dir = "/tmp/rut_serve_loader_import";
    write_file(dir, "auth.rut", "func jwtAuth() -> i32 => 200\n");
    const std::string path = write_file(
        dir,
        "main.rut",
        "import \"auth.rut\"\n"
        "route GET \"/users\" { if jwtAuth() == 200 { return 200 } else { return 500 } }\n");

    LoadedProgram program;
    LoadError err;
    REQUIRE(load_rut_program(path.c_str(), program, err));
    CHECK_EQ(program.config.route_count, 1u);
    program.destroy();
}

TEST(serve_loader, unknown_import_reports_copied_detail) {
    // The diagnostic detail (the imported name) lives in analyzer storage
    // that is freed when load_rut_program returns; format_load_error must
    // still read it (the loader copies it into LoadError).
    const std::string path = write_file("/tmp/rut_serve_loader_badimport",
                                        "main.rut",
                                        "import \"missing.rut\"\n"
                                        "route GET \"/\" { return 200 }\n");

    LoadedProgram program;
    LoadError err;
    CHECK_FALSE(load_rut_program(path.c_str(), program, err));
    CHECK(err.has_diag);

    char msg[256];
    format_load_error(err, msg, sizeof(msg));
    // Detail names the unresolved import — proves the copy survived return.
    CHECK(contains(msg, "missing.rut"));
    program.destroy();
}

TEST(serve_loader, format_read_stage_without_diag) {
    LoadError err;
    err.stage = LoadStage::Read;
    err.has_diag = false;

    char msg[128];
    const u32 n = format_load_error(err, msg, sizeof(msg));
    CHECK_GT(n, 0u);
    CHECK(contains(msg, "read source file"));
    CHECK(contains(msg, "failed"));
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
