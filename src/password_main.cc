#include "rut/common/types.h"
#include "rut/runtime/crypto_c.h"
#include "rut/runtime/password.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

namespace {
using namespace rut;
volatile sig_atomic_t interrupted = 0;
void on_signal(int) {
    interrupted = 1;
}

struct Signals {
    static constexpr int kSignals[] = {SIGINT, SIGTERM, SIGHUP, SIGPIPE};
    struct sigaction previous[4]{};
    u32 installed = 0;
    bool init() {
        for (u32 i = 0; i < 4; ++i) {
            struct sigaction action{};
            action.sa_handler = i == 3 ? SIG_IGN : on_signal;
            sigemptyset(&action.sa_mask);
            if (sigaction(kSignals[i], &action, &previous[i]) != 0) return false;
            ++installed;
        }
        return true;
    }
    ~Signals() {
        while (installed) {
            --installed;
            (void)sigaction(kSignals[installed], &previous[installed], nullptr);
        }
    }
};

struct Secret {
    char data[kPasswordMaxBytes + 1]{};
    u32 length = 0;
    ~Secret() { rut_crypto_clear_v1(data, sizeof(data)); }
};

bool write_all(int fd, const char* data, u32 length) {
    while (length && !interrupted) {
        const auto kN = write(fd, data, length);
        if (kN > 0) {
            data += kN;
            length -= static_cast<u32>(kN);
        } else if (kN < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return length == 0;
}
bool message(const char* text) {
    return write_all(STDERR_FILENO, text, static_cast<u32>(strlen(text)));
}
int failure(const char* text) {
    // Diagnostic output must still be attempted after cancellation.
    (void)write(STDERR_FILENO, text, strlen(text));
    return 2;
}

struct Terminal {
    struct termios saved{};
    bool active = false;
    bool init() {
        if (tcgetattr(STDIN_FILENO, &saved) != 0) return false;
        active = true;
        auto hidden = saved;
        hidden.c_lflag &= ~(ECHO | ECHONL | ICANON);
        hidden.c_cc[VMIN] = 1;
        hidden.c_cc[VTIME] = 0;
        return tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) == 0;
    }
    bool restore() {
        if (!active) return true;
        int rc = 0;
        do {
            rc = tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved);
        } while (rc < 0 && errno == EINTR);
        if (rc == 0) active = false;
        return rc == 0;
    }
    ~Terminal() { (void)restore(); }
};

bool terminal_control_key(const Terminal& terminal, int index, unsigned char byte) {
#ifdef _POSIX_VDISABLE
    if (terminal.saved.c_cc[index] == _POSIX_VDISABLE) return false;
#endif
    return byte == terminal.saved.c_cc[index];
}

bool read_password(Secret& password) {
    Terminal terminal;
    const bool kInteractive = isatty(STDIN_FILENO) == 1;
    if (kInteractive && (!terminal.init() || !message("Password: "))) return false;
    bool ok = false;
    if (kInteractive) {
        char input[128];
        bool too_long = false;
        while (!interrupted && !ok) {
            const auto kN = read(STDIN_FILENO, input, sizeof(input));
            if (kN < 0 && errno == EINTR) continue;
            if (kN < 0) break;
            if (kN == 0) {
                ok = true;
                break;
            }
            for (u32 i = 0; i < static_cast<u32>(kN); ++i) {
                const auto kByte = static_cast<unsigned char>(input[i]);
                if (kByte == '\n' || terminal_control_key(terminal, VEOF, kByte)) {
                    ok = true;
                    break;
                }
                if (too_long) continue;
                if (terminal_control_key(terminal, VERASE, kByte)) {
                    if (password.length != 0) {
                        password.data[--password.length] = '\0';
                    }
                    continue;
                }
                if (terminal_control_key(terminal, VKILL, kByte)) {
                    rut_crypto_clear_v1(password.data, password.length);
                    password.length = 0;
                    continue;
                }
                if (password.length == kPasswordMaxBytes) {
                    too_long = true;
                    continue;
                }
                password.data[password.length++] = static_cast<char>(kByte);
            }
            rut_crypto_clear_v1(input, sizeof(input));
        }
        ok = ok && !too_long;
    } else {
        while (!interrupted && password.length < sizeof(password.data)) {
            const auto kN = read(STDIN_FILENO,
                                 password.data + password.length,
                                 sizeof(password.data) - password.length);
            if (kN < 0 && errno == EINTR) continue;
            if (kN < 0) break;
            if (kN == 0) {
                ok = true;
                break;
            }
            password.length += static_cast<u32>(kN);
        }
    }
    if (!terminal.restore()) ok = false;
    if (kInteractive) (void)message("\n");
    return ok && !interrupted && password.length > 0 && password.length <= kPasswordMaxBytes;
}

bool read_record(const char* path, char (&record)[kPasswordRecordBytes + 2]) {
    const int kFd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (kFd < 0) return false;
    struct stat st{};
    bool ok = fstat(kFd, &st) == 0 && S_ISREG(st.st_mode) &&
              (st.st_size == kPasswordRecordBytes || st.st_size == kPasswordRecordBytes + 1);
    u32 used = 0;
    while (ok && used < sizeof(record) && !interrupted) {
        const auto kN = read(kFd, record + used, sizeof(record) - used);
        if (kN < 0 && errno == EINTR) continue;
        if (kN < 0) {
            ok = false;
            break;
        }
        if (kN == 0) break;
        used += static_cast<u32>(kN);
    }
    if (close(kFd) != 0) ok = false;
    return ok && !interrupted &&
           (used == kPasswordRecordBytes ||
            (used == kPasswordRecordBytes + 1 && record[kPasswordRecordBytes] == '\n')) &&
           password_record_valid({record, kPasswordRecordBytes});
}

bool sync_fd(int fd) {
    int rc = 0;
    do {
        rc = fsync(fd);
    } while (rc < 0 && errno == EINTR);
    return rc == 0;
}

struct Directory {
    int fd = -1;
    const char* name = nullptr;
    bool init(const char* path) {
        const size_t kLength = strlen(path);
        if (kLength == 0 || kLength >= 4096) return false;
        char parent[4096];
        const char* slash = strrchr(path, '/');
        name = slash ? slash + 1 : path;
        if (name[0] == '\0' || strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return false;
        if (slash) {
            const size_t kPrefix = slash == path ? 1 : static_cast<size_t>(slash - path);
            __builtin_memcpy(parent, path, kPrefix);
            parent[kPrefix] = '\0';
        } else {
            parent[0] = '.';
            parent[1] = '\0';
        }
        fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) return false;
        struct stat st{};
        // Publication uses directory-relative names. Require a parent controlled
        // by this administrative user, without group/other rename access.
        return fstat(fd, &st) == 0 && st.st_uid == geteuid() && (st.st_mode & 0022) == 0;
    }
    ~Directory() {
        if (fd >= 0) close(fd);
    }
    const char* publish(const char* record) const {
        constexpr auto kPrefix = lit_str("$rut-pbkdf2-sha256$600000$");
        char temporary[64] = ".rut-password-";
        constexpr u32 kOffset = sizeof(".rut-password-") - 1;
        // The newly generated public salt already supplies 128 random bits.
        __builtin_memcpy(temporary + kOffset, record + kPrefix.len, 32);
        temporary[kOffset + 32] = '\0';
        const int kFile =
            openat(fd, temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (kFile < 0) return "cannot create private temporary record\n";
        bool ok = fchmod(kFile, 0600) == 0 && write_all(kFile, record, kPasswordRecordBytes + 1) &&
                  sync_fd(kFile);
        if (close(kFile) != 0) ok = false;
        if (!ok || interrupted) {
            (void)unlinkat(fd, temporary, 0);
            return "record preparation failed or was interrupted\n";
        }
        // Same-directory hard-link publication is atomic and never replaces an
        // existing file, symlink or competing creator's result.
        const int kLinked = linkat(fd, temporary, fd, name, 0);
        const bool kRemoved = unlinkat(fd, temporary, 0) == 0;
        // Once linked, finish the directory commit even if cancellation arrived.
        const bool kSynced = sync_fd(fd);
        if (kLinked != 0) return "record not created: destination exists or publication failed\n";
        if (!kRemoved || !kSynced)
            return "record published, but cleanup/directory sync failed; inspect the destination\n";
        return nullptr;
    }
};

constexpr char kUsage[] =
    "Usage: rut-password hash [--output FILE]\n"
    "       rut-password verify RECORD_FILE\n"
    "       rut-password --help\n"
    "Passwords come only from stdin, never argv or environment.\n"
    "Terminal input hides echo and omits its final Enter; redirected input is\n"
    "1..1024 exact bytes (including NUL/newlines), read to EOF.\n"
    "Hash writes a random-salt canonical record plus LF to stdout, or atomically\n"
    "creates a new 0600 FILE in a private owned directory. Existing paths stay.\n"
    "Verify accepts a canonical regular record file with at most one final LF.\n"
    "Exit: 0 success/match, 1 mismatch, 2 usage/input/OS/crypto failure.\n";
}  // namespace

int main(int argc, char** argv) {
    Signals signals;
    if (!signals.init()) return failure("cannot install input cancellation handlers\n");
    if (argc == 2 && strcmp(argv[1], "--help") == 0)
        return write_all(STDOUT_FILENO, kUsage, sizeof(kUsage) - 1) ? 0 : 2;
    const bool kHash = argc >= 2 && strcmp(argv[1], "hash") == 0;
    const bool kVerify = argc == 3 && strcmp(argv[1], "verify") == 0;
    const char* output = nullptr;
    if (kHash && argc == 4 && strcmp(argv[2], "--output") == 0) output = argv[3];
    if ((!kHash && !kVerify) || (kHash && argc != 2 && !output)) return failure(kUsage);
    Directory directory;
    if (output && !directory.init(output))
        return failure("output requires an owned directory without group/other write permission\n");
    char record[kPasswordRecordBytes + 2]{};
    if (kVerify && !read_record(argv[2], record))
        return failure("cannot read a canonical regular record file\n");
    Secret password;
    if (!read_password(password))
        return failure("password input failed, was interrupted, or is outside 1..1024 bytes\n");
    if (kVerify) {
        const bool kMatched =
            password_verify({password.data, password.length}, {record, kPasswordRecordBytes});
        if (interrupted) return failure("verification interrupted\n");
        return kMatched ? 0 : 1;
    }
    u32 length = 0;
    if (!password_hash({password.data, password.length}, record, kPasswordRecordBytes, length) ||
        length != kPasswordRecordBytes || interrupted)
        return failure("password hashing failed or was interrupted\n");
    record[length++] = '\n';
    if (output) {
        if (const char* error = directory.publish(record)) return failure(error);
    } else if (!write_all(STDOUT_FILENO, record, length)) {
        return failure("cannot write the password record\n");
    }
    return 0;
}
