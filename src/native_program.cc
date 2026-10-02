#include "rut/jit/runtime_helpers.h"
#include "rut/native_artifact.h"
#include "rut/runtime/cache_table.h"
#include "rut/runtime/response_body_files.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/memfd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

namespace rut {
namespace {
volatile sig_atomic_t g_startup_cancelled = 0;
void startup_cancel_handler(int) {
    g_startup_cancelled = 1;
}

struct StartupSignalScope {
    struct sigaction old_int{};
    struct sigaction old_term{};
    bool int_installed = false;
    bool term_installed = false;
    sigset_t old_mask{};
    bool mask_saved = false;
    struct sigaction old_chld{};
    bool chld_installed = false;
    StartupSignalScope() {
        sigset_t blocked{};
        sigemptyset(&blocked);
        sigaddset(&blocked, SIGINT);
        sigaddset(&blocked, SIGTERM);
        if (sigprocmask(SIG_BLOCK, &blocked, &old_mask) == 0) mask_saved = true;
        g_startup_cancelled = 0;
        struct sigaction action{};
        action.sa_handler = startup_cancel_handler;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGINT, &action, &old_int) == 0) {
            int_installed = true;
        }
        if (int_installed && sigaction(SIGTERM, &action, &old_term) == 0) {
            term_installed = true;
        } else if (int_installed) {
            sigaction(SIGINT, &old_int, nullptr);
            int_installed = false;
        }
        struct sigaction chld_default{};
        chld_default.sa_handler = SIG_DFL;
        sigemptyset(&chld_default.sa_mask);
        if (sigaction(SIGCHLD, &chld_default, &old_chld) == 0) chld_installed = true;
        if (mask_saved) sigprocmask(SIG_SETMASK, &old_mask, nullptr);
    }
    bool finish() {
        if (!int_installed && !term_installed) return g_startup_cancelled != 0;
        if (mask_saved) {
            sigset_t blocked{};
            sigemptyset(&blocked);
            sigaddset(&blocked, SIGINT);
            sigaddset(&blocked, SIGTERM);
            sigprocmask(SIG_BLOCK, &blocked, nullptr);
        }
        if (term_installed) sigaction(SIGTERM, &old_term, nullptr);
        if (int_installed) {
            sigaction(SIGINT, &old_int, nullptr);
        }
        if (chld_installed) sigaction(SIGCHLD, &old_chld, nullptr);
        const bool cancelled = g_startup_cancelled != 0;
        int_installed = false;
        term_installed = false;
        chld_installed = false;
        if (mask_saved) sigprocmask(SIG_SETMASK, &old_mask, nullptr);
        g_startup_cancelled = 0;
        return cancelled;
    }
    ~StartupSignalScope() { (void)finish(); }
};

#ifdef __linux__
int create_artifact_memfd() {
    // MFD_EXEC is required by kernels that enforce W^X for anonymous files.
    // Older kernels reject the new flag, but their memfds are executable by
    // default, so retain that compatibility path.
    unsigned int flags = MFD_CLOEXEC | MFD_ALLOW_SEALING;
    constexpr unsigned kMfdExec = 0x0010U;
#ifdef MFD_EXEC
    static_assert(MFD_EXEC == kMfdExec);
#endif
    int fd = static_cast<int>(syscall(SYS_memfd_create, "rut-program", flags | kMfdExec));
    if (fd >= 0) return fd;
    if (errno != EINVAL && errno != ENOSYS && errno != EOPNOTSUPP) return -1;
    return static_cast<int>(syscall(SYS_memfd_create, "rut-program", flags));
}
#endif

bool compiler_path(char* path, u32 cap) {
#ifdef __linux__
    ssize_t n = readlink("/proc/self/exe", path, cap - 1);
    if (n <= 0 || static_cast<u32>(n) >= cap - 1) return false;
    path[n] = '\0';
#elif defined(__APPLE__)
    if (_NSGetExecutablePath(path, &cap) != 0) return false;
#else
    return false;
#endif
    char* slash = strrchr(path, '/');
    if (!slash || static_cast<u32>(slash + 1 - path) + sizeof("rut-compile") > cap) return false;
    memcpy(slash + 1, "rut-compile", sizeof("rut-compile"));
    return true;
}
}  // namespace

void NativeProgram::destroy() {
    cache_registry_unpublish_if_owner(this);
    for (u32 i = 0; i < regex_count; i++) rut_helper_regex_free(regex_handles[i]);
    regex_count = 0;
    regex_handles = nullptr;
    close_response_body_files(config);
    if (library) dlclose(library);
    library = nullptr;
    if (artifact_fd >= 0) close(artifact_fd);
    artifact_fd = -1;
    arena.destroy();
    config.~RouteConfig();
    ::new (&config) RouteConfig();
    has_listener = false;
    listener = {};
    access_log = {};
}

bool load_native_program(
    const char* source, NativeProgram& out, char* error, u32 error_size, u8 opt) {
    if (!error || !error_size) return false;
    error[0] = '\0';
    auto fail = [&](const char* message) {
        snprintf(error, error_size, "%s", message);
        out.destroy();
        return false;
    };
    if (out.library || out.config.route_count || out.arena.current) {
        snprintf(error, error_size, "native program destination is already populated");
        return false;
    }
    StartupSignalScope startup_signals;
    if (opt > 3) return fail("invalid optimization level");
    char compiler[4096];
    if (!compiler_path(compiler, sizeof(compiler)))
        return fail("cannot locate sibling rut-compile");
    int channel[2];
    if (pipe(channel) != 0) return fail("cannot create compiler output pipe");
    // Startup precedes shard threads. CLOEXEC prevents the linker and compiler
    // from accidentally keeping the consumer end open.
    fcntl(channel[0], F_SETFD, FD_CLOEXEC);
    fcntl(channel[1], F_SETFD, FD_CLOEXEC);
    char level[] = {static_cast<char>('0' + opt), '\0'};
    const pid_t parent_pid = getpid();
    pid_t child = fork();
    if (child == 0) {
        close(channel[0]);
        setpgid(0, 0);
        struct sigaction default_action{};
        default_action.sa_handler = SIG_DFL;
        sigemptyset(&default_action.sa_mask);
        sigaction(SIGINT, &default_action, nullptr);
        sigaction(SIGTERM, &default_action, nullptr);
#ifdef __linux__
        // The compiler must never survive a killed or cancelled server
        // startup. Check the parent PID after arming the signal to close the
        // fork/parent-death race.
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent_pid) _exit(127);
#endif
        if (dup2(channel[1], STDOUT_FILENO) < 0) _exit(127);
        if (fcntl(STDOUT_FILENO, F_SETFD, 0) != 0) _exit(127);
        if (channel[1] != STDOUT_FILENO) close(channel[1]);
        execl(compiler, compiler, source, level, nullptr);
        const char message[] = "Cannot execute sibling rut-compile\n";
        (void)write(2, message, sizeof(message) - 1);
        _exit(127);
    }
    close(channel[1]);
    if (child < 0) {
        close(channel[0]);
        return fail("cannot start rut-compile");
    }
    setpgid(child, child);
    struct Child {
        pid_t pid;
        int fd;
        int status = 0;
        bool reaped = false;
        bool wait() {
            close(fd);
            fd = -1;
            for (;;) {
                if (g_startup_cancelled) {
                    cancel();
                    return false;
                }
                pid_t n = waitpid(pid, &status, WNOHANG);
                if (n == pid) {
                    reaped = true;
                    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
                }
                if (n < 0 && errno != EINTR) return false;
                poll(nullptr, 0, 10);
            }
        }
        void cancel() {
            if (!reaped) {
                if (kill(-pid, SIGKILL) != 0) kill(pid, SIGKILL);
            }
            while (!reaped) {
                pid_t result = waitpid(pid, &status, WNOHANG);
                if (result == pid || (result < 0 && errno == ECHILD)) {
                    reaped = true;
                    break;
                }
                if (result < 0 && errno != EINTR) break;
                poll(nullptr, 0, 10);
            }
        }
        ~Child() {
            if (fd >= 0) close(fd);
            if (!reaped) {
                // Failure closes the pipe and stops a blocked producer before
                // reaping it; no child may outlive a failed load.
                kill(pid, SIGKILL);
                while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
                }
            }
        }
    } producer{child, channel[0]};
    auto read_all = [&](void* data, u64 size) {
        auto* ptr = static_cast<u8*>(data);
        while (size) {
            if (g_startup_cancelled) return false;
            struct pollfd wait_fd{producer.fd, POLLIN, 0};
            int ready = poll(&wait_fd, 1, 50);
            if (ready < 0 && errno == EINTR) continue;
            if (ready == 0) continue;
            if (ready < 0) return false;
            ssize_t n = read(producer.fd, ptr, size);
            if (n < 0 && errno == EINTR) {
                if (g_startup_cancelled) return false;
                continue;
            }
            if (n <= 0) return false;
            ptr += n;
            size -= static_cast<u64>(n);
        }
        return true;
    };
    native::StreamHeader stream{};
    if (!read_all(&stream, sizeof(stream))) {
        producer.cancel();
        if (g_startup_cancelled) return fail("startup cancelled");
        return fail("rut-compile failed (see diagnostic above)");
    }
    if (stream.magic != native::kMagic || stream.version != native::kVersion ||
        memcmp(stream.build_id, native::kBuildId, sizeof(stream.build_id)) != 0)
        return fail("rut and rut-compile build mismatch");
    if (stream.artifact_size == 0 || stream.artifact_size > (u64{1} << 30))
        return fail("invalid compiler artifact size");
    char artifact[4096];
#ifdef __linux__
    out.artifact_fd = create_artifact_memfd();
    if (out.artifact_fd < 0) return fail("cannot allocate anonymous compiler artifact");
    snprintf(artifact, sizeof(artifact), "/proc/self/fd/%d", out.artifact_fd);
#else
    strcpy(artifact, "/tmp/rut-program-XXXXXX");
    out.artifact_fd = mkstemp(artifact);
    if (out.artifact_fd < 0) return fail("cannot allocate compiler artifact");
    fcntl(out.artifact_fd, F_SETFD, FD_CLOEXEC);
    struct TempCleanup {
        const char* path;
        ~TempCleanup() { unlink(path); }
    } temp{artifact};
#endif
    // Drain while the producer runs: waiting first deadlocks once the pipe fills.
    u8 buffer[65536];
    u64 remaining = stream.artifact_size;
    while (remaining) {
        u64 n = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        if (!read_all(buffer, n))
            return fail(g_startup_cancelled ? "startup cancelled" : "truncated compiler artifact");
        u64 pos = 0;
        while (pos < n) {
            ssize_t written = write(out.artifact_fd, buffer + pos, n - pos);
            if (written < 0 && errno == EINTR) {
                if (g_startup_cancelled) return fail("startup cancelled");
                continue;
            }
            if (written <= 0) return fail("cannot receive compiler artifact");
            pos += static_cast<u64>(written);
        }
        remaining -= n;
    }
    u8 extra;
    ssize_t tail = -1;
    for (;;) {
        if (g_startup_cancelled) {
            producer.cancel();
            return fail("startup cancelled");
        }
        struct pollfd wait_fd{producer.fd, POLLIN, 0};
        int ready = poll(&wait_fd, 1, 50);
        if (ready < 0 && errno == EINTR) continue;
        if (ready == 0) continue;
        if (ready < 0) {
            producer.cancel();
            return fail("cannot read compiler artifact");
        }
        tail = read(producer.fd, &extra, 1);
        if (tail < 0 && errno == EINTR) continue;
        break;
    }
    if (tail != 0) return fail("invalid compiler artifact framing");
    if (g_startup_cancelled) {
        producer.cancel();
        return fail("startup cancelled");
    }
    const bool producer_ok = producer.wait();
    const bool startup_cancelled = startup_signals.finish();
    if (startup_cancelled) return fail("startup cancelled");
    if (!producer_ok) return fail("rut-compile failed (see diagnostic above)");
#ifdef __linux__
    if (fcntl(out.artifact_fd,
              F_ADD_SEALS,
              F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL) != 0)
        return fail("cannot seal compiler artifact");
#endif
    out.library = dlopen(artifact, RTLD_NOW | RTLD_LOCAL);
    if (!out.library) return fail(dlerror());
    auto* bytes = static_cast<const u8*>(dlsym(out.library, "rut_native_config"));
    auto* size = static_cast<const u64*>(dlsym(out.library, "rut_native_config_size"));
    if (!bytes || !size || *size < sizeof(native::Header))
        return fail("missing native configuration");
    const auto& h = *reinterpret_cast<const native::Header*>(bytes);
    auto& c = out.config;
    if (h.magic != native::kMagic || h.version != native::kVersion || h.config_size != sizeof(c) ||
        h.size != *size || h.metadata_size != native::metadata_size(c) ||
        h.route_count > c.kMaxRoutes ||
        (h.dispatch != RouteConfig::DispatchKind::ArtJit &&
         h.dispatch != RouteConfig::DispatchKind::SegmentTrie))
        return fail("native configuration ABI mismatch");
    u64 pos = sizeof(h);
    auto take = [&](u64 n) -> const u8* {
        if (n > h.size - pos) return nullptr;
        const u8* result = bytes + pos;
        pos += n;
        return result;
    };
    const u8* routes = take(sizeof(RouteEntry) * h.route_count);
    const u8* metadata = take((h.metadata_size + 7u) & ~7u);
    const u8* reloc_data = take(sizeof(native::Relocation) * h.relocation_count);
    const u8* symbol_data = take(sizeof(native::Symbol) * h.symbol_count);
    const u8* regex_data = take(sizeof(native::Regex) * h.regex_count);
    if (!routes || !metadata || !reloc_data || !symbol_data || !regex_data)
        return fail("truncated native configuration");
    memcpy(static_cast<void*>(c.routes),
           static_cast<const void*>(routes),
           sizeof(RouteEntry) * h.route_count);
    memcpy(reinterpret_cast<u8*>(&c) + native::metadata_offset(c), metadata, h.metadata_size);
    if (c.upstream_count > c.kMaxUpstreams || c.timer_count > c.kMaxTimers ||
        c.cache_instance_count > c.kMaxCacheInstances ||
        c.response_body_count > c.kMaxResponseBodies ||
        c.header_pool_used > c.kMaxHeaderPoolEntries ||
        c.response_policy_count > c.kMaxResponsePolicies ||
        c.failure_policy_count > kMaxForwardFailurePolicies ||
        c.policy_bundle_count > c.kMaxForwardPolicyBundles ||
        c.target_transform_count > kMaxForwardTargetTransforms ||
        c.redirect_policy_count > c.kMaxRedirectPolicies ||
        c.strict_local_response_policy_count > c.kMaxStrictLocalResponsePolicies)
        return fail("invalid native configuration counts");
    // The artifact has no live compiler addresses. Restore only declared byte
    // views and native symbols, then reconstruct indices against the new owner.
    const auto* relocs = reinterpret_cast<const native::Relocation*>(reloc_data);
    const auto* symbols = reinterpret_cast<const native::Symbol*>(symbol_data);
    auto field_valid = [&](u32 field) {
        return field <= sizeof(c) - sizeof(void*) &&
               (field + sizeof(void*) <= sizeof(RouteEntry) * h.route_count ||
                (field >= native::metadata_offset(c) &&
                 field + sizeof(void*) <= native::metadata_offset(c) + h.metadata_size));
    };
    for (u32 i = 0; i < h.relocation_count; i++) {
        const auto& r = relocs[i];
        if (!field_valid(r.field) ||
            (r.blob_offset ? r.blob_offset >= h.size : r.config_offset >= sizeof(c)))
            return fail("invalid native relocation");
        const void* ptr =
            r.blob_offset ? bytes + r.blob_offset : reinterpret_cast<u8*>(&c) + r.config_offset;
        memcpy(
            reinterpret_cast<u8*>(&c) + r.field, reinterpret_cast<const void*>(&ptr), sizeof(ptr));
    }
    for (u32 i = 0; i < h.symbol_count; i++) {
        const auto& s = symbols[i];
        if (!field_valid(s.field) || !memchr(s.name, '\0', sizeof(s.name)))
            return fail("invalid native symbol");
        void* fn = dlsym(out.library, s.name);
        if (!fn) return fail("missing native handler symbol");
        memcpy(reinterpret_cast<u8*>(&c) + s.field, reinterpret_cast<const void*>(&fn), sizeof(fn));
    }
    if (!out.arena.init(4096)) return fail("cannot allocate native program arena");
    out.regex_handles = out.arena.alloc_array<void*>(h.regex_count);
    if (h.regex_count && !out.regex_handles) return fail("cannot allocate regex handles");
    const auto* regexes = reinterpret_cast<const native::Regex*>(regex_data);
    for (u32 i = 0; i < h.regex_count; i++) {
        const auto& r = regexes[i];
        if (!memchr(r.symbol, '\0', sizeof(r.symbol)) || r.database_offset >= h.size ||
            r.database_size > h.size - r.database_offset)
            return fail("invalid native regex record");
        auto** slot = static_cast<void**>(dlsym(out.library, r.symbol));
        if (!slot) return fail("missing native regex slot");
        void* handle = rut_helper_regex_deserialize(
            reinterpret_cast<const char*>(bytes + r.database_offset), r.database_size);
        if (!handle) return fail("cannot initialize native regex");
        out.regex_handles[out.regex_count++] = handle;
        *slot = handle;
    }
    if (h.dispatch == RouteConfig::DispatchKind::SegmentTrie) c.use_segment_trie();
    for (u32 i = 0; i < h.route_count; i++) {
        const auto& r = c.routes[i];
        if (r.path_len >= RouteEntry::kMaxPathLen || r.path[r.path_len] != '\0' ||
            !RouteConfig::is_routable_path(r.path) || !c.populate_dispatch_state(r))
            return fail("cannot rebuild native route index");
        c.route_count++;
    }
    if (!c.strict_local_response_table_is_valid()) return fail("invalid native response metadata");
    attach_response_body_files(c);
    out.has_listener = h.has_listener;
    out.listener = h.listener;
    out.access_log = h.access_log;
    return true;
}

void activate_native_program(const NativeProgram& p) {
    u32 caps[RouteConfig::kMaxCacheInstances]{};
    u64 ids[RouteConfig::kMaxCacheInstances]{};
    for (u32 i = 0; i < p.config.cache_instance_count; i++) {
        const auto& e = p.config.cache_instances[i];
        caps[i] = e.capacity;
        ids[i] = cache_instance_identity(e.name, e.name_len);
    }
    cache_registry_publish(caps, ids, p.config.cache_instance_count, &p);
}
}  // namespace rut
