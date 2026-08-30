#include "fixture_privileged_listener.h"
#include "rut/serve_loader.h"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <string>

#include <unistd.h>

#ifndef RUT_ENABLE_JIT
#error "the privileged listener public-loader proof must only be built with JIT enabled"
#endif

namespace listener = rut::test::fixture_privileged_listener;

int main() {
    constexpr listener::ListenerPlan plan{0x0a010203u, 0x0a010204u, 8080u};
    char path[] = "/tmp/rut-listener-source-XXXXXX";
    const int fd = mkstemp(path);
    if (fd < 0) return 1;
    std::string source;
    listener::Diagnostic diagnostic;
    bool ok = listener::build_listener_source(
        plan, listener::ListenerSourceKind::Exact, source, diagnostic);
    std::size_t offset = 0u;
    while (ok && offset < source.size()) {
        const ssize_t count = write(fd, source.data() + offset, source.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            ok = false;
            break;
        }
        offset += static_cast<std::size_t>(count);
    }
    if (close(fd) != 0) ok = false;
    rut::LoadedProgram program;
    rut::LoadError error;
    if (ok) ok = rut::load_rut_program(path, program, error, rut::jit::OptLevel::O2);
    if (ok)
        ok = program.has_listener && program.listener.address == rut::ListenerAddress::IPv4Exact &&
             program.listener.ipv4_host == plan.positive_ipv4 && program.listener.port == plan.port;
    program.destroy();
    if (unlink(path) != 0) ok = false;
    if (!ok) {
        std::fprintf(stderr, "FAIL: ordinary source did not compile through JIT public loader\n");
        return 1;
    }
    std::puts("PASS: #358 JIT public listener loader");
    return 0;
}
