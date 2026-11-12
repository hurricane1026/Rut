#include "rut/common/types.h"
#include "rut/runtime/consumer_registry.h"
#include "rut/runtime/crypto_c.h"
#include "rut/runtime/json.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
using namespace rut;

struct Buffer {
    char data[json::kMaxBytes + 1]{};
    u32 len = 0;
    Str view() const { return {data, len}; }
    ~Buffer() { rut_crypto_clear_v1(data, sizeof(data)); }
};
struct SensitiveDocument : json::Document {
    ~SensitiveDocument() { rut_crypto_clear_v1(this, sizeof(*this)); }
};

int failure(const char* message) {
    (void)write(STDERR_FILENO, message, strlen(message));
    return 2;
}
bool write_all(int fd, Str value) {
    while (value.len) {
        const auto kN = write(fd, value.ptr, value.len);
        if (kN < 0 && errno == EINTR) continue;
        if (kN <= 0) return false;
        value = value.slice(static_cast<u32>(kN), value.len);
    }
    return true;
}
bool sync_fd(int fd) {
    int rc;
    do {
        rc = fsync(fd);
    } while (rc < 0 && errno == EINTR);
    return rc == 0;
}
bool read_private(const char* path, Buffer& result) {
    const int kFd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (kFd < 0) return false;
    struct stat st{};
    bool ok = fstat(kFd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
              (st.st_mode & 0077) == 0 && st.st_size > 0 && st.st_size <= json::kMaxBytes;
    while (ok && result.len < sizeof(result.data)) {
        const auto kN = read(kFd, result.data + result.len, sizeof(result.data) - result.len);
        if (kN < 0 && errno == EINTR) continue;
        if (kN < 0) {
            ok = false;
            break;
        }
        if (kN == 0) break;
        result.len += static_cast<u32>(kN);
    }
    if (close(kFd) != 0) ok = false;
    return ok && result.len > 0 && result.len <= json::kMaxBytes;
}

// Immutable output avoids overwriting either a published snapshot or another
// administrator's result. A private parent prevents hostile rename races.
const char* publish(const char* path, Str value) {
    char parent[4096];
    const size_t kLength = strlen(path);
    if (!kLength || kLength >= sizeof(parent)) return "invalid output path\n";
    const char* slash = strrchr(path, '/');
    const char* name = slash ? slash + 1 : path;
    if (!*name || strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return "invalid output path\n";
    const size_t kPrefix = slash ? (slash == path ? 1 : static_cast<size_t>(slash - path)) : 1;
    if (slash)
        __builtin_memcpy(parent, path, kPrefix);
    else
        parent[0] = '.';
    parent[kPrefix] = '\0';
    const int kDirectory = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (kDirectory < 0) return "cannot open output directory\n";
    struct stat st{};
    if (fstat(kDirectory, &st) != 0 || st.st_uid != geteuid() || (st.st_mode & 0022) != 0) {
        close(kDirectory);
        return "output requires an owned directory without group/other write permission\n";
    }
    char temporary[64];
    int file = -1;
    for (u32 attempt = 0; attempt < 32; ++attempt) {
        (void)snprintf(temporary,
                       sizeof(temporary),
                       ".rut-consumers-%ld-%u",
                       static_cast<long>(getpid()),
                       attempt);
        file = openat(
            kDirectory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (file >= 0 || errno != EEXIST) break;
    }
    if (file < 0) {
        close(kDirectory);
        return "cannot create private temporary snapshot\n";
    }
    bool ok = fchmod(file, 0600) == 0 && write_all(file, value) && sync_fd(file);
    if (close(file) != 0) ok = false;
    const bool kLinked = ok && linkat(kDirectory, temporary, kDirectory, name, 0) == 0;
    const bool kRemoved = unlinkat(kDirectory, temporary, 0) == 0;
    const bool kSynced = sync_fd(kDirectory);
    close(kDirectory);
    if (!kLinked) return "snapshot not created: preparation failed or destination exists\n";
    if (!kRemoved || !kSynced)
        return "snapshot published but cleanup/directory sync failed; inspect destination\n";
    return nullptr;
}

u32 field(json::Document& doc, u32 object, Str name) {
    if (object >= doc.count || doc.nodes[object].kind != json::Kind::Object) return json::kNone;
    for (u32 n = doc.nodes[object].child; n != json::kNone; n = doc.nodes[n].next) {
        json::Writer key{doc.scratch};
        if (doc.string(doc.nodes[n].key, key) && name.eq({key.data, key.len})) return n;
    }
    return json::kNone;
}
bool equal(json::Document& a, u32 ai, json::Document& b, u32 bi) {
    char left[64], right[64];
    json::Writer x{left, sizeof(left)}, y{right, sizeof(right)};
    return a.string(ai, x) && b.string(bi, y) && Str{left, x.len}.eq({right, y.len});
}
bool id_valid(json::Document& doc, u32 id) {
    char bytes[64];
    json::Writer value{bytes, sizeof(bytes)};
    if (!doc.string(id, value) || !value.len) return false;
    for (u32 i = 0; i < value.len; ++i)
        if (bytes[i] < 0x21 || bytes[i] > 0x7e) return false;
    return true;
}
u32 find(json::Document& doc, u32 array, json::Document& key_doc, u32 key, bool records) {
    if (array >= doc.count || doc.nodes[array].kind != json::Kind::Array) return json::kNone;
    for (u32 n = doc.nodes[array].child; n != json::kNone; n = doc.nodes[n].next) {
        if (n >= doc.count || n >= json::kMaxNodes) return json::kNone;
        const u32 kId = records ? field(doc, n, lit_str("id")) : n;
        if (equal(doc, kId, key_doc, key)) return n;
    }
    return json::kNone;
}

bool merge_records(json::Document& base,
                   u32 original,
                   json::Document& patch,
                   u32 updates,
                   u32 removals,
                   json::Writer& output) {
    if (original >= base.count || base.nodes[original].kind != json::Kind::Array ||
        updates >= patch.count || removals >= patch.count ||
        patch.nodes[updates].kind != json::Kind::Array ||
        patch.nodes[removals].kind != json::Kind::Array)
        return false;
    // Every operation has exactly one target. Unknown removals and an ID in both
    // lists are mistakes, rather than silently successful partial updates.
    for (u32 n = patch.nodes[updates].child; n != json::kNone; n = patch.nodes[n].next) {
        const u32 kId = field(patch, n, lit_str("id"));
        if (!id_valid(patch, kId) || find(patch, updates, patch, kId, true) != n ||
            find(patch, removals, patch, kId, false) != json::kNone)
            return false;
    }
    for (u32 n = patch.nodes[removals].child; n != json::kNone; n = patch.nodes[n].next) {
        if (!id_valid(patch, n) || find(patch, removals, patch, n, false) != n ||
            find(base, original, patch, n, true) == json::kNone)
            return false;
    }
    output.put('[');
    bool first = true;
    for (u32 n = base.nodes[original].child; n != json::kNone; n = base.nodes[n].next) {
        const u32 kId = field(base, n, lit_str("id"));
        if (find(patch, removals, base, kId, false) != json::kNone ||
            find(patch, updates, base, kId, true) != json::kNone)
            continue;
        if (!first) output.put(',');
        first = false;
        if (!base.write(n, output)) return false;
    }
    for (u32 n = patch.nodes[updates].child; n != json::kNone; n = patch.nodes[n].next) {
        if (!first) output.put(',');
        first = false;
        if (!patch.write(n, output)) return false;
    }
    output.put(']');
    return output.ok;
}

bool apply(json::Document& base, json::Document& patch, json::Writer& output) {
    if (!patch.count || patch.nodes[0].kind != json::Kind::Object) return false;
    u32 fields = 0;
    for (u32 n = patch.nodes[0].child; n != json::kNone; n = patch.nodes[n].next) ++fields;
    if (fields != 4) return false;
    output.text(lit_str("{\"version\":1,\"consumers\":"));
    if (!merge_records(base,
                       field(base, 0, lit_str("consumers")),
                       patch,
                       field(patch, 0, lit_str("consumers")),
                       field(patch, 0, lit_str("removeConsumers")),
                       output))
        return false;
    output.text(lit_str(",\"credentials\":"));
    if (!merge_records(base,
                       field(base, 0, lit_str("credentials")),
                       patch,
                       field(patch, 0, lit_str("credentials")),
                       field(patch, 0, lit_str("removeCredentials")),
                       output))
        return false;
    output.put('}');
    return output.ok;
}

bool inspect(json::Document& doc, json::Writer& output) {
    output.text(lit_str("{\"version\":1,\"consumers\":"));
    const u32 kConsumers = field(doc, 0, lit_str("consumers"));
    if (kConsumers >= doc.count || !doc.write(kConsumers, output)) return false;
    output.text(lit_str(",\"credentials\":["));
    const u32 kCredentials = field(doc, 0, lit_str("credentials"));
    if (kCredentials >= doc.count || doc.nodes[kCredentials].kind != json::Kind::Array)
        return false;
    bool first = true;
    for (u32 n = doc.nodes[kCredentials].child; n != json::kNone; n = doc.nodes[n].next) {
        if (!first) output.put(',');
        first = false;
        if (!doc.write(n, output, field(doc, n, lit_str("secret")), {}, true)) return false;
    }
    output.text(lit_str("]}\n"));
    return output.ok;
}

constexpr char kUsage[] =
    "Usage: rut-consumers init OUTPUT\n"
    "       rut-consumers validate INPUT\n"
    "       rut-consumers inspect INPUT\n"
    "       rut-consumers plan INPUT CHANGES\n"
    "       rut-consumers apply INPUT CHANGES OUTPUT\n"
    "       rut-consumers --help\n"
    "Inputs must be owned private regular JSON files, at most 8192 bytes.\n"
    "Changes contains four arrays: consumers, credentials (full-record upserts),\n"
    "removeConsumers and removeCredentials (existing IDs). References must remain valid.\n"
    "Output is a new atomic 0600 snapshot; existing paths are never replaced.\n"
    "Inspect and plan omit credential secrets. Plan validates without creating files.\n"
    "No command publishes to running gateways.\n"
    "Exit: 0 success, 2 usage/validation/OS failure.\n";
}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && strcmp(argv[1], "--help") == 0)
        return write_all(STDOUT_FILENO, {kUsage, sizeof(kUsage) - 1}) ? 0 : 2;
    const bool kInit = argc == 3 && strcmp(argv[1], "init") == 0;
    const bool kValidate = argc == 3 && strcmp(argv[1], "validate") == 0;
    const bool kInspect = argc == 3 && strcmp(argv[1], "inspect") == 0;
    const bool kPlan = argc == 4 && strcmp(argv[1], "plan") == 0;
    const bool kApply = argc == 5 && strcmp(argv[1], "apply") == 0;
    if (!kInit && !kValidate && !kInspect && !kPlan && !kApply) return failure(kUsage);
    if (kInit) {
        const char* error =
            publish(argv[2], lit_str("{\"version\":1,\"consumers\":[],\"credentials\":[]}"));
        return error ? failure(error) : 0;
    }
    Buffer input;
    SensitiveDocument base;
    if (!read_private(argv[2], input)) return failure("cannot read private registry file\n");
    if (!consumer_registry_valid(base, input.view()))
        return failure("invalid Consumer registry snapshot\n");
    if (kValidate) return 0;
    Buffer result;
    json::Writer output{result.data, kInspect ? json::kMaxBytes + 1 : json::kMaxBytes};
    if (kInspect) {
        if (!inspect(base, output)) return failure("cannot produce redacted registry\n");
        return write_all(STDOUT_FILENO, {output.data, output.len}) ? 0 : 2;
    }
    Buffer changes;
    SensitiveDocument patch;
    if (!read_private(argv[3], changes)) return failure("cannot read private changes file\n");
    if (!patch.parse(changes.view()) || !apply(base, patch, output))
        return failure("invalid Consumer registry changes\n");
    SensitiveDocument checked;
    if (!consumer_registry_valid(checked, {output.data, output.len}))
        return failure("invalid replacement Consumer registry snapshot\n");
    if (kPlan) {
        Buffer redacted;
        json::Writer preview{redacted.data, sizeof(redacted.data)};
        if (!inspect(checked, preview)) return failure("cannot produce redacted registry\n");
        return write_all(STDOUT_FILENO, {preview.data, preview.len}) ? 0 : 2;
    }
    const char* error = publish(argv[4], {output.data, output.len});
    return error ? failure(error) : 0;
}
