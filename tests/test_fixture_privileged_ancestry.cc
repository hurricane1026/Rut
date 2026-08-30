#include "fixture_privileged_ancestry.h"
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

namespace ancestry = rut::test::fixture_privileged_ancestry;
namespace identity = rut::test::fixture_identity_bundle;
namespace worker = rut::test::fixture_worker_protocol;

namespace {

bool check(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "FAIL: %s\n", message);
    return condition;
}

size_t fd_count() {
    DIR* directory = opendir("/proc/self/fd");
    if (directory == nullptr) return 0;
    size_t count = 0;
    while (readdir(directory) != nullptr) ++count;
    closedir(directory);
    return count;
}

}  // namespace

int main() {
    bool ok = true;
    const pid_t parent = getpid();
    int ready[2] = {-1, -1};
    if (pipe2(ready, O_CLOEXEC) != 0) return 1;
    const pid_t child = fork();
    if (child < 0) {
        close(ready[0]);
        close(ready[1]);
        std::perror("fork");
        return 1;
    }
    if (child == 0) {
        close(ready[0]);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent || setpgid(0, 0) != 0)
            _exit(125);
        const unsigned char marker = 1;
        if (write(ready[1], &marker, 1) != 1) _exit(125);
        close(ready[1]);
        for (;;) pause();
    }
    close(ready[1]);
    unsigned char marker = 0;
    ok = check(worker::read_exact(ready[0], &marker, 1, 1000) && marker == 1,
               "child setup synchronization failed") &&
         ok;
    close(ready[0]);

    ancestry::ancestry::AncestryBundle bundle;
    std::string diagnostic;
    const size_t baseline_fds = fd_count();
    const bool collected =
        ancestry::collect_ancestry(child,
                                   parent,
                                   bundle,
                                   std::chrono::steady_clock::now() + std::chrono::seconds(2),
                                   diagnostic);
    ok = check(collected, "real child ancestry collection failed") && ok;
    ok = check(bundle.nodes.size() == 1, "collector did not retain exactly one node") && ok;
    ok = check(bundle.nodes.size() == 1 && bundle.nodes[0].fds.size() == identity::kFdsPerRole,
               "collector did not retain six descriptors") &&
         ok;
    const size_t collected_fds = fd_count();
    ok = check(collected_fds >= baseline_fds + identity::kFdsPerRole,
               "collector did not transfer owned descriptors") &&
         ok;
    ok = check(
             !ancestry::collect_ancestry(child,
                                         child,
                                         bundle,
                                         std::chrono::steady_clock::now() + std::chrono::seconds(2),
                                         diagnostic) &&
                 bundle.nodes.empty() && diagnostic.find("phase=boundary") != std::string::npos,
             "invalid ancestry boundary was accepted") &&
         ok;
    ok = check(!ancestry::collect_ancestry(
                   child,
                   parent,
                   bundle,
                   std::chrono::steady_clock::now() - std::chrono::milliseconds(1),
                   diagnostic) &&
                   bundle.nodes.empty() && diagnostic.find("phase=deadline") != std::string::npos,
               "expired collector deadline did not fail closed") &&
         ok;
    ok = check(fd_count() == baseline_fds, "collector failure leaked descriptors") && ok;

    worker::ProcIdentity process;
    ok = check(worker::read_proc(child, process, false), "child identity read failed") && ok;
    identity::ProcessIdentityEvidence source;
    // The expired collection deliberately cleared the bundle; recollect for
    // the binder test so this also exercises ownership after a failure.
    if (ok)
        ok = check(ancestry::collect_ancestry(
                       child,
                       parent,
                       bundle,
                       std::chrono::steady_clock::now() + std::chrono::seconds(2),
                       diagnostic),
                   "recollection after failure failed") &&
             ok;
    if (ok)
        ok = check(identity::extract_process_identity_evidence(
                       bundle.nodes[0], identity::Role::Ancestry, source, diagnostic),
                   "failed to extract node evidence") &&
             ok;

    ancestry::RetainedAnchorEvidence retained;
    std::vector<identity::ProcessIdentityEvidence> records{source};
    ok = check(ancestry::bind_retained_anchor_evidence(records, retained, diagnostic) &&
                   retained.pid == source.identity.pid && retained.start == source.identity.start,
               "one-record retained binder rejected valid evidence") &&
         ok;
    std::vector<identity::ProcessIdentityEvidence> none;
    ok = check(!ancestry::bind_retained_anchor_evidence(none, retained, diagnostic),
               "zero-record retained binder was accepted") &&
         ok;
    records.push_back(source);
    ok = check(!ancestry::bind_retained_anchor_evidence(records, retained, diagnostic),
               "multi-record retained binder was accepted") &&
         ok;

    bundle.close();
    (void)kill(child, SIGKILL);
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    ok = check(waited == child && WIFSIGNALED(status), "child cleanup failed") && ok;
    return ok ? 0 : 1;
}
