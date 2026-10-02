#include "rut/native_artifact.h"
#include "rut/serve_loader.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
bool write_all(const void* bytes, rut::u64 size) {
    const auto* data = static_cast<const rut::u8*>(bytes);
    while (size) {
        ssize_t n = write(STDOUT_FILENO, data, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        data += n;
        size -= static_cast<rut::u64>(n);
    }
    return true;
}
}  // namespace
int main(int argc, char** argv) {
    if (argc != 3 || strlen(argv[2]) != 1 || argv[2][0] < '0' || argv[2][0] > '3' ||
        isatty(STDOUT_FILENO)) {
        fprintf(
            stderr,
            "Internal helper: rut-compile SOURCE OPT_LEVEL(0..3); binary output requires a pipe\n");
        return 2;
    }
    char directory[] = "/tmp/rut-compile-XXXXXX";
    if (!mkdtemp(directory)) {
        perror("rut-compile directory");
        return 1;
    }
    char artifact[4096];
    snprintf(artifact, sizeof(artifact), "%s/program.so", directory);
    struct Cleanup {
        const char* artifact;
        const char* directory;
        ~Cleanup() {
            unlink(artifact);
            rmdir(directory);
        }
    } cleanup{artifact, directory};
    static rut::LoadedProgram program;
    rut::LoadError error;
    bool ok = rut::load_rut_program(argv[1],
                                    program,
                                    error,
                                    static_cast<rut::jit::OptLevel>(argv[2][0] - '0'),
                                    ~rut::u64{0},
                                    true);
    if (!ok) {
        char message[512];
        rut::format_load_error(error, message, sizeof(message));
        fprintf(stderr, "%s: %s\n", argv[1], message);
    } else if (!(ok = rut::write_native_program(program, artifact))) {
        fprintf(stderr, "Failed to emit native artifact\n");
    }
    program.destroy();
    if (!ok) return 1;
    int fd = open(artifact, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 1;
    struct stat st{};
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        close(fd);
        return 1;
    }
    rut::native::StreamHeader header{};
    header.magic = rut::native::kMagic;
    header.version = rut::native::kVersion;
    memcpy(header.build_id, rut::native::kBuildId, sizeof(header.build_id));
    header.artifact_size = static_cast<rut::u64>(st.st_size);
    ok = write_all(&header, sizeof(header));
    char buffer[65536];
    while (ok) {
        ssize_t n = read(fd, buffer, sizeof(buffer));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            ok = false;
            break;
        }
        if (n == 0) break;
        ok = write_all(buffer, static_cast<rut::u64>(n));
    }
    close(fd);
    return ok ? 0 : 1;
}
