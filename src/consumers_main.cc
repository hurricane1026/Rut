#include "rut/common/types.h"
#include "rut/runtime/auth.h"
#include "rut/runtime/consumer_registry.h"
#include "rut/runtime/crypto_c.h"
#include "rut/runtime/hash.h"
#include "rut/runtime/json.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/random.h>
#elif defined(__APPLE__)
#include <sys/random.h>
#endif

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
struct GeneratedSecret {
    u8 random[32]{};
    char hex[64]{};
    ~GeneratedSecret() {
        rut_crypto_clear_v1(random, sizeof(random));
        rut_crypto_clear_v1(hex, sizeof(hex));
    }
    bool generate() {
#ifdef __linux__
        if (getrandom(random, sizeof(random), GRND_NONBLOCK) !=
            static_cast<ssize_t>(sizeof(random)))
            return false;
#else
        if (getentropy(random, sizeof(random)) != 0) return false;
#endif
        constexpr char kDigits[] = "0123456789abcdef";
        for (u32 i = 0; i < sizeof(random); ++i) {
            const size_t kOffset = static_cast<size_t>(i) * 2;
            hex[kOffset] = kDigits[random[i] >> 4];
            hex[kOffset + 1] = kDigits[random[i] & 0x0f];
        }
        return true;
    }
};
struct SensitiveKeyText {
    char bytes[65]{};
    ~SensitiveKeyText() { rut_crypto_clear_v1(bytes, sizeof(bytes)); }
};
struct SensitiveHashText {
    char bytes[kMaxHashHexBytes]{};
    ~SensitiveHashText() { rut_crypto_clear_v1(bytes, sizeof(bytes)); }
};
struct OutputTarget {
    int directory = -1;
    char basename[256]{};
    ~OutputTarget() {
        if (directory >= 0) close(directory);
    }
};
struct OutputPair {
    OutputTarget snapshot;
    OutputTarget key;
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

bool output_target(const char* path, OutputTarget& target, struct stat& directory_stat) {
    char parent[4096];
    const size_t length = strlen(path);
    if (!length || length >= sizeof(parent)) return false;
    const char* slash = strrchr(path, '/');
    const char* name = slash ? slash + 1 : path;
    const size_t name_length = strlen(name);
    if (!name_length || name_length >= sizeof(target.basename) || strcmp(name, ".") == 0 ||
        strcmp(name, "..") == 0)
        return false;
    if (slash) {
        const size_t prefix = slash == path ? 1 : static_cast<size_t>(slash - path);
        __builtin_memcpy(parent, path, prefix);
        parent[prefix] = '\0';
    } else {
        parent[0] = '.';
        parent[1] = '\0';
    }
    target.directory = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (target.directory < 0 || fstat(target.directory, &directory_stat) != 0 ||
        !S_ISDIR(directory_stat.st_mode) || directory_stat.st_uid != geteuid() ||
        (directory_stat.st_mode & 0022) != 0)
        return false;
    __builtin_memcpy(target.basename, name, name_length + 1);
    return true;
}

bool output_pair(const char* snapshot_path, const char* key_path, OutputPair& pair) {
    struct stat snapshot_directory{}, key_directory{};
    if (!output_target(snapshot_path, pair.snapshot, snapshot_directory) ||
        !output_target(key_path, pair.key, key_directory) ||
        snapshot_directory.st_dev != key_directory.st_dev ||
        snapshot_directory.st_ino != key_directory.st_ino ||
        strcmp(pair.snapshot.basename, pair.key.basename) == 0)
        return false;
    struct stat existing{};
    if (fstatat(pair.snapshot.directory, pair.snapshot.basename, &existing, AT_SYMLINK_NOFOLLOW) ==
            0 ||
        errno != ENOENT)
        return false;
    if (fstatat(pair.key.directory, pair.key.basename, &existing, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT)
        return false;
    return true;
}

enum class PublishAtResult : u8 { NotPublished, Published, Uncertain };
PublishAtResult publish_at(int directory, const char* name, Str value) {
    char temporary[64];
    int file = -1;
    for (u32 attempt = 0; attempt < 32; ++attempt) {
        (void)snprintf(temporary,
                       sizeof(temporary),
                       ".rut-consumers-%ld-%u",
                       static_cast<long>(getpid()),
                       attempt);
        file = openat(
            directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (file >= 0 || errno != EEXIST) break;
    }
    if (file < 0) return PublishAtResult::NotPublished;
    bool ready = fchmod(file, 0600) == 0 && write_all(file, value) && sync_fd(file);
    if (close(file) != 0) ready = false;
    const bool linked = ready && linkat(directory, temporary, directory, name, 0) == 0;
    const bool removed = unlinkat(directory, temporary, 0) == 0;
    const bool synced = sync_fd(directory);
    if (!linked && removed && synced) return PublishAtResult::NotPublished;
    return linked && removed && synced ? PublishAtResult::Published : PublishAtResult::Uncertain;
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
bool provision_id_valid(Str value) {
    if (!value.ptr || !value.len || value.len > 64) return false;
    for (u32 i = 0; i < value.len; ++i) {
        const auto byte = static_cast<u8>(value.ptr[i]);
        if (byte < 0x21 || byte > 0x7e) return false;
    }
    return true;
}
bool field_equals(json::Document& doc, u32 node, Str expected) {
    char bytes[65];
    json::Writer value{bytes, sizeof(bytes)};
    return doc.string(node, value) && value.ok && Str{bytes, value.len}.eq(expected);
}
u32 bounded_argument(const char* value, u32 capacity) {
    u32 length = 0;
    while (length < capacity && value[length]) ++length;
    return length < capacity ? length : 0;
}
bool contains_id(json::Document& doc, u32 array, Str id, bool records) {
    if (array >= doc.count || doc.nodes[array].kind != json::Kind::Array) return false;
    for (u32 n = doc.nodes[array].child; n != json::kNone; n = doc.nodes[n].next)
        if (field_equals(doc, records ? field(doc, n, lit_str("id")) : n, id)) return true;
    return false;
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
        u32 hidden = field(doc, n, lit_str("secret"));
        if (hidden == json::kNone) hidden = field(doc, n, lit_str("secretSha256"));
        if (!doc.write(n, output, hidden, {}, true)) return false;
    }
    output.text(lit_str("]}\n"));
    return output.ok;
}

bool audit_string_equal(json::Document& before, u32 left, json::Document& after, u32 right) {
    json::Writer a{before.scratch}, b{after.scratch};
    return before.string(left, a) && after.string(right, b) &&
           Str{a.data, a.len}.eq({b.data, b.len});
}

bool audit_value_equal(json::Document& before, u32 left, json::Document& after, u32 right) {
    if (left == json::kNone || right == json::kNone) return left == right;
    const auto kind = before.nodes[left].kind;
    if (kind != after.nodes[right].kind) return false;
    if (kind == json::Kind::String) return audit_string_equal(before, left, after, right);
    if (kind == json::Kind::Number) {
        i64 a = 0, b = 0;
        return json::integer(before.raw(left), a) && json::integer(after.raw(right), b) && a == b;
    }
    if (kind != json::Kind::Array) return before.raw(left).eq(after.raw(right));
    // The only metadata arrays are validated unique group sets.
    u32 left_count = 0, right_count = 0;
    for (u32 a = before.nodes[left].child; a != json::kNone; a = before.nodes[a].next) {
        ++left_count;
        bool found = false;
        for (u32 b = after.nodes[right].child; b != json::kNone; b = after.nodes[b].next)
            found |= audit_string_equal(before, a, after, b);
        if (!found) return false;
    }
    for (u32 b = after.nodes[right].child; b != json::kNone; b = after.nodes[b].next) ++right_count;
    return left_count == right_count;
}

bool audit_metadata_equal(json::Document& before, u32 left, json::Document& after, u32 right) {
    const Str fields[] = {lit_str("id"),
                          lit_str("consumerId"),
                          lit_str("method"),
                          lit_str("enabled"),
                          lit_str("groups"),
                          lit_str("notBefore"),
                          lit_str("expiresAt")};
    for (Str name : fields)
        if (!audit_value_equal(before, field(before, left, name), after, field(after, right, name)))
            return false;
    return true;
}

bool audit_key_digest(json::Document& doc, u32 record, SensitiveHashText& digest) {
    const u32 hashed = field(doc, record, lit_str("secretSha256"));
    if (hashed != json::kNone) {
        json::Writer text{digest.bytes, sizeof(digest.bytes)};
        return doc.string(hashed, text) && text.len == 64;
    }
    const u32 raw = field(doc, record, lit_str("secret"));
    Buffer secret;
    json::Writer text{secret.data, json::kMaxBytes};
    u32 length = 0;
    return doc.string(raw, text) &&
           hash_hex(
               HashAlgorithm::Sha256, {secret.data, text.len}, {}, false, digest.bytes, length) &&
           length == 64;
}

bool audit_key_changes(json::Document& before,
                       u32 left,
                       json::Document& after,
                       u32 right,
                       bool& changed,
                       bool& representation_changed) {
    const bool left_hash = field(before, left, lit_str("secretSha256")) != json::kNone;
    const bool right_hash = field(after, right, lit_str("secretSha256")) != json::kNone;
    representation_changed = left_hash != right_hash;
    if (!audit_string_equal(before,
                            field(before, left, lit_str("method")),
                            after,
                            field(after, right, lit_str("method")))) {
        changed = true;
        return true;
    }
    if (!left_hash && !right_hash) {
        changed = !audit_string_equal(before,
                                      field(before, left, lit_str("secret")),
                                      after,
                                      field(after, right, lit_str("secret")));
        return true;
    }
    SensitiveHashText a, b;
    if (!audit_key_digest(before, left, a) || !audit_key_digest(after, right, b)) return false;
    changed = !Str{a.bytes, 64}.eq({b.bytes, 64});
    return true;
}

bool audit_record(json::Document& doc, u32 record, bool credential, json::Writer& output) {
    u32 hidden = json::kNone;
    if (credential) {
        hidden = field(doc, record, lit_str("secret"));
        if (hidden == json::kNone) hidden = field(doc, record, lit_str("secretSha256"));
    }
    return doc.write(record, output, hidden, {}, true);
}

bool audit_records(json::Document& before,
                   json::Document& after,
                   Str name,
                   bool credential,
                   json::Writer& output) {
    const u32 left = field(before, 0, name), right = field(after, 0, name);
    output.text(lit_str("{\"added\":["));
    bool first = true;
    for (u32 n = after.nodes[right].child; n != json::kNone; n = after.nodes[n].next) {
        if (find(before, left, after, field(after, n, lit_str("id")), true) != json::kNone)
            continue;
        if (!first) output.put(',');
        first = false;
        if (!audit_record(after, n, credential, output)) return false;
    }
    output.text(lit_str("],\"removed\":["));
    first = true;
    for (u32 n = before.nodes[left].child; n != json::kNone; n = before.nodes[n].next) {
        if (find(after, right, before, field(before, n, lit_str("id")), true) != json::kNone)
            continue;
        if (!first) output.put(',');
        first = false;
        if (!audit_record(before, n, credential, output)) return false;
    }
    output.text(lit_str("],\"changed\":["));
    first = true;
    for (u32 n = before.nodes[left].child; n != json::kNone; n = before.nodes[n].next) {
        const u32 other = find(after, right, before, field(before, n, lit_str("id")), true);
        if (other == json::kNone) continue;
        bool key_changed = false, representation_changed = false;
        if (credential &&
            !audit_key_changes(before, n, after, other, key_changed, representation_changed))
            return false;
        if (!key_changed && !representation_changed &&
            audit_metadata_equal(before, n, after, other))
            continue;
        if (!first) output.put(',');
        first = false;
        output.text(lit_str("{\"before\":"));
        if (!audit_record(before, n, credential, output)) return false;
        output.text(lit_str(",\"after\":"));
        if (!audit_record(after, other, credential, output)) return false;
        if (credential) {
            output.text(lit_str(",\"keyChanged\":"));
            output.text(key_changed ? lit_str("true") : lit_str("false"));
            output.text(lit_str(",\"keyRepresentationChanged\":"));
            output.text(representation_changed ? lit_str("true") : lit_str("false"));
        }
        output.put('}');
    }
    output.text(lit_str("]}"));
    return output.ok;
}

bool audit_diff(json::Document& before, json::Document& after, json::Writer& output) {
    output.text(lit_str("{\"consumers\":"));
    if (!audit_records(before, after, lit_str("consumers"), false, output)) return false;
    output.text(lit_str(",\"credentials\":"));
    if (!audit_records(before, after, lit_str("credentials"), true, output)) return false;
    output.text(lit_str("}\n"));
    return output.ok;
}

bool hash_keys(json::Document& doc, json::Writer& output) {
    const u32 consumers = field(doc, 0, lit_str("consumers"));
    const u32 credentials = field(doc, 0, lit_str("credentials"));
    if (consumers >= doc.count || credentials >= doc.count ||
        doc.nodes[credentials].kind != json::Kind::Array)
        return false;
    output.text(lit_str("{\"version\":1,\"consumers\":"));
    if (!doc.write(consumers, output)) return false;
    output.text(lit_str(",\"credentials\":["));
    bool first = true;
    for (u32 record = doc.nodes[credentials].child; record != json::kNone;
         record = doc.nodes[record].next) {
        if (!first) output.put(',');
        first = false;
        const u32 method_node = field(doc, record, lit_str("method"));
        const bool has_hash = field(doc, record, lit_str("secretSha256")) != json::kNone;
        char method_bytes[16];
        json::Writer method_writer{method_bytes, sizeof(method_bytes)};
        if (!doc.string(method_node, method_writer)) return false;
        const Str method{method_bytes, method_writer.len};
        const bool convert =
            !has_hash && (method.eq(lit_str("bearer")) || method.eq(lit_str("header")));
        if (!convert) {
            if (!doc.write(record, output)) return false;
            continue;
        }
        SensitiveKeyText secret_buffer;
        json::Writer secret_writer{secret_buffer.bytes, sizeof(secret_buffer.bytes)};
        const u32 secret_node = field(doc, record, lit_str("secret"));
        if (!doc.string(secret_node, secret_writer) || secret_writer.len != 64) {
            return false;
        }
        const Str secret{secret_buffer.bytes, secret_writer.len};
        if (!sha256_hex_format_valid(secret)) return false;
        SensitiveHashText digest;
        u32 digest_len = 0;
        if (!hash_hex(HashAlgorithm::Sha256, secret, {}, false, digest.bytes, digest_len) ||
            digest_len != 64)
            return false;
        output.put('{');
        bool field_first = true;
        for (u32 member = doc.nodes[record].child; member != json::kNone;
             member = doc.nodes[member].next) {
            char key_bytes[32];
            json::Writer key_writer{key_bytes, sizeof(key_bytes)};
            if (!doc.string(doc.nodes[member].key, key_writer)) {
                return false;
            }
            if (Str{key_bytes, key_writer.len}.eq(lit_str("secret"))) continue;
            if (!field_first) output.put(',');
            field_first = false;
            if (!doc.write(doc.nodes[member].key, output)) return false;
            output.put(':');
            if (!doc.write(member, output)) return false;
        }
        if (!field_first) output.put(',');
        output.text(lit_str("\"secretSha256\":\""));
        output.text({digest.bytes, digest_len});
        output.text(lit_str("\"}"));
        if (!output.ok) return false;
    }
    output.text(lit_str("]}"));
    return output.ok;
}

bool rotate_key_change(
    json::Document& doc, u32 source, Str replacement_id, Str digest, json::Writer& output) {
    output.text(lit_str("{\"consumers\":[],\"credentials\":["));
    if (!doc.write(source, output, field(doc, source, lit_str("enabled")), lit_str("false")))
        return false;
    output.text(lit_str(",{\"id\":"));
    if (!json::quote(replacement_id, output)) return false;
    for (u32 member = doc.nodes[source].child; member != json::kNone;
         member = doc.nodes[member].next) {
        if (member == field(doc, source, lit_str("id")) ||
            member == field(doc, source, lit_str("enabled")) ||
            member == field(doc, source, lit_str("secret")) ||
            member == field(doc, source, lit_str("secretSha256")))
            continue;
        output.put(',');
        if (!doc.write(doc.nodes[member].key, output)) return false;
        output.put(':');
        if (!doc.write(member, output)) return false;
    }
    output.text(lit_str(",\"enabled\":true,\"secretSha256\":\""));
    output.text(digest);
    output.text(lit_str("\"}],\"removeConsumers\":[],\"removeCredentials\":[]}"));
    return output.ok;
}

bool prune_cutoff(const char* text, i64& cutoff) {
    if (!text || text[0] < '1' || text[0] > '9') return false;
    u64 value = 0;
    constexpr u64 kMax = ~u64{0} >> 1;
    for (u32 i = 0; text[i]; ++i) {
        if (text[i] < '0' || text[i] > '9') return false;
        const u64 digit = static_cast<u64>(text[i] - '0');
        if (value > (kMax - digit) / 10) return false;
        value = value * 10 + digit;
    }
    cutoff = static_cast<i64>(value);
    return true;
}

bool prune_credentials(json::Document& doc, i64 cutoff, json::Writer& output) {
    output.text(lit_str("{\"version\":1,\"consumers\":"));
    if (!doc.write(field(doc, 0, lit_str("consumers")), output)) return false;
    output.text(lit_str(",\"credentials\":["));
    const u32 credentials = field(doc, 0, lit_str("credentials"));
    bool first = true;
    for (u32 record = doc.nodes[credentials].child; record != json::kNone;
         record = doc.nodes[record].next) {
        const u32 expiry = field(doc, record, lit_str("expiresAt"));
        i64 expires_at = 0;
        if (expiry != json::kNone && !json::integer(doc.raw(expiry), expires_at)) return false;
        if (doc.raw(field(doc, record, lit_str("enabled"))).eq(lit_str("false")) ||
            (expires_at > 0 && expires_at <= cutoff))
            continue;
        if (!first) output.put(',');
        first = false;
        if (!doc.write(record, output)) return false;
    }
    output.text(lit_str("]}"));
    return output.ok;
}

int prune_credentials_command(const char* source,
                              const char* cutoff_text,
                              const char* destination) {
    i64 cutoff = 0;
    if (!prune_cutoff(cutoff_text, cutoff)) return failure("invalid credential pruning cutoff\n");
    Buffer input;
    SensitiveDocument base;
    if (!read_private(source, input)) return failure("cannot read private registry file\n");
    if (!consumer_registry_valid(base, input.view()))
        return failure("invalid Consumer registry snapshot\n");
    Buffer result;
    json::Writer output{result.data, json::kMaxBytes};
    if (!prune_credentials(base, cutoff, output))
        return failure("cannot encode pruned Consumer registry snapshot\n");
    SensitiveDocument checked;
    if (!consumer_registry_valid(checked, {result.data, output.len}))
        return failure("invalid pruned Consumer registry snapshot\n");
    const char* error = publish(destination, {result.data, output.len});
    return error ? failure(error) : 0;
}

constexpr char kUsage[] =
    "Usage: rut-consumers init OUTPUT\n"
    "       rut-consumers validate INPUT\n"
    "       rut-consumers inspect INPUT\n"
    "       rut-consumers diff BEFORE AFTER\n"
    "       rut-consumers plan INPUT CHANGES\n"
    "       rut-consumers apply INPUT CHANGES OUTPUT\n"
    "       rut-consumers generate-key INPUT CONSUMER_ID CREDENTIAL_ID METHOD OUTPUT\n"
    "       rut-consumers generate-key-verifier INPUT CONSUMER_ID CREDENTIAL_ID METHOD "
    "SNAPSHOT_OUTPUT KEY_OUTPUT\n"
    "       rut-consumers rotate-key-verifier INPUT OLD_CREDENTIAL_ID NEW_CREDENTIAL_ID "
    "SNAPSHOT_OUTPUT KEY_OUTPUT\n"
    "       rut-consumers prune-credentials INPUT CUTOFF_UNIX_SECONDS OUTPUT\n"
    "       rut-consumers hash-keys INPUT OUTPUT\n"
    "       rut-consumers --help\n"
    "Inputs must be owned private regular JSON files, at most 8192 bytes.\n"
    "Changes contains four arrays: consumers, credentials (full-record upserts),\n"
    "removeConsumers and removeCredentials (existing IDs). References must remain valid.\n"
    "Output is a new atomic 0600 snapshot; existing paths are never replaced.\n"
    "Inspect and plan redact credential secrets and SHA-256 verifiers. Plan validates without "
    "creating files.\n"
    "Diff validates both snapshots and emits structured redacted changes without creating files.\n"
    "No command publishes to running gateways.\n"
    "generate-key supports bearer/header and creates a new 32-byte random key in an immutable "
    "snapshot.\n"
    "generate-key-verifier writes a verifier snapshot and the generated raw key to separate new "
    "private files.\n"
    "rotate-key-verifier disables the old key and inherits its owner, method, groups and time "
    "bounds.\n"
    "prune-credentials removes disabled or expired-at-cutoff credentials without reading the "
    "clock.\n"
    "hash-keys converts raw bearer/header keys in the 64-lowercase-hex generated-key profile.\n"
    "Exit: 0 success, 2 usage/validation/OS failure.\n";
}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && strcmp(argv[1], "--help") == 0)
        return write_all(STDOUT_FILENO, {kUsage, sizeof(kUsage) - 1}) ? 0 : 2;
    if (argc == 5 && strcmp(argv[1], "prune-credentials") == 0)
        return prune_credentials_command(argv[2], argv[3], argv[4]);
    const bool kInit = argc == 3 && strcmp(argv[1], "init") == 0;
    const bool kValidate = argc == 3 && strcmp(argv[1], "validate") == 0;
    const bool kInspect = argc == 3 && strcmp(argv[1], "inspect") == 0;
    const bool kDiff = argc == 4 && strcmp(argv[1], "diff") == 0;
    const bool kPlan = argc == 4 && strcmp(argv[1], "plan") == 0;
    const bool kApply = argc == 5 && strcmp(argv[1], "apply") == 0;
    const bool kGenerateKey = argc == 7 && strcmp(argv[1], "generate-key") == 0;
    const bool kGenerateKeyVerifier = argc == 8 && strcmp(argv[1], "generate-key-verifier") == 0;
    const bool kRotateKeyVerifier = argc == 7 && strcmp(argv[1], "rotate-key-verifier") == 0;
    const bool kHashKeys = argc == 4 && strcmp(argv[1], "hash-keys") == 0;
    if (!kInit && !kValidate && !kInspect && !kDiff && !kPlan && !kApply && !kGenerateKey &&
        !kGenerateKeyVerifier && !kRotateKeyVerifier && !kHashKeys)
        return failure(kUsage);
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
    if (kDiff) {
        Buffer input_after;
        SensitiveDocument after;
        if (!read_private(argv[3], input_after))
            return failure("cannot read private registry file\n");
        if (!consumer_registry_valid(after, input_after.view()))
            return failure("invalid Consumer registry snapshot\n");
        char bytes[4 * json::kMaxBytes];
        json::Writer output{bytes, sizeof(bytes)};
        if (!audit_diff(base, after, output))
            return failure("cannot produce redacted registry diff\n");
        return write_all(STDOUT_FILENO, {bytes, output.len}) ? 0 : 2;
    }
    if (kHashKeys) {
        Buffer result;
        json::Writer hashed{result.data, json::kMaxBytes};
        if (!hash_keys(base, hashed))
            return failure("registry cannot be converted to SHA-256 key verifiers\n");
        SensitiveDocument checked;
        if (!consumer_registry_valid(checked, {result.data, hashed.len}))
            return failure("converted registry has invalid or ambiguous credentials\n");
        const char* error = publish(argv[3], {result.data, hashed.len});
        return error ? failure(error) : 0;
    }
    if (kGenerateKey) {
        const u32 consumer_length = bounded_argument(argv[3], 65);
        const u32 credential_length = bounded_argument(argv[4], 65);
        const u32 method_length = bounded_argument(argv[5], 16);
        const Str consumer_id{argv[3], consumer_length};
        const Str credential_id{argv[4], credential_length};
        const Str method{argv[5], method_length};
        if (!provision_id_valid(consumer_id) || !provision_id_valid(credential_id) ||
            !(method.eq(lit_str("bearer")) || method.eq(lit_str("header"))))
            return failure("invalid Consumer ID, credential ID, or key method\n");
        const u32 consumers = field(base, 0, lit_str("consumers"));
        const u32 credentials = field(base, 0, lit_str("credentials"));
        if (!contains_id(base, consumers, consumer_id, true))
            return failure("Consumer does not exist in registry snapshot\n");
        if (contains_id(base, credentials, credential_id, true))
            return failure("credential ID already exists in registry snapshot\n");

        GeneratedSecret secret;
        if (!secret.generate()) return failure("operating-system random key generation failed\n");
        Buffer change_bytes;
        json::Writer change_output{change_bytes.data, json::kMaxBytes};
        change_output.text(lit_str("{\"consumers\":[],\"credentials\":[{\"id\":"));
        if (!json::quote(credential_id, change_output))
            return failure("cannot encode key change\n");
        change_output.text(lit_str(",\"consumerId\":"));
        if (!json::quote(consumer_id, change_output)) return failure("cannot encode key change\n");
        change_output.text(lit_str(",\"method\":\""));
        change_output.text(method);
        change_output.text(lit_str("\",\"secret\":\""));
        change_output.text({secret.hex, sizeof(secret.hex)});
        change_output.text(
            lit_str("\",\"enabled\":true}],\"removeConsumers\":[],\"removeCredentials\":[]}"));
        if (!change_output.ok) return failure("key change exceeds registry capacity\n");
        SensitiveDocument patch;
        if (!patch.parse({change_bytes.data, change_output.len}))
            return failure("cannot encode key change\n");
        Buffer result;
        json::Writer output{result.data, json::kMaxBytes};
        if (!apply(base, patch, output))
            return failure("generated registry snapshot exceeds supported capacity\n");
        SensitiveDocument checked;
        if (!consumer_registry_valid(checked, {result.data, output.len}))
            return failure("generated registry snapshot is invalid\n");
        const char* error = publish(argv[6], {result.data, output.len});
        return error ? failure(error) : 0;
    }
    if (kGenerateKeyVerifier || kRotateKeyVerifier) {
        const u32 consumer_length = bounded_argument(argv[3], 65);
        const u32 credential_length = bounded_argument(argv[4], 65);
        const u32 method_length = bounded_argument(argv[5], 16);
        const Str consumer_id{argv[3], consumer_length};
        const Str credential_id{argv[4], credential_length};
        const Str method{argv[5], method_length};
        const u32 consumers = field(base, 0, lit_str("consumers"));
        const u32 credentials = field(base, 0, lit_str("credentials"));
        u32 source = json::kNone;
        if (kRotateKeyVerifier) {
            if (!provision_id_valid(consumer_id) || !provision_id_valid(credential_id))
                return failure("invalid old or new credential ID\n");
            u32 count = 0;
            for (u32 n = base.nodes[credentials].child; n != json::kNone; n = base.nodes[n].next) {
                ++count;
                if (field_equals(base, field(base, n, lit_str("id")), consumer_id)) source = n;
            }
            if (count >= 64) return failure("rotation exceeds credential capacity\n");
            if (source == json::kNone ||
                !base.raw(field(base, source, lit_str("enabled"))).eq(lit_str("true")) ||
                !(field_equals(base, field(base, source, lit_str("method")), lit_str("bearer")) ||
                  field_equals(base, field(base, source, lit_str("method")), lit_str("header"))))
                return failure("rotation requires an enabled bearer/header credential\n");
        } else {
            if (!provision_id_valid(consumer_id) || !provision_id_valid(credential_id) ||
                !(method.eq(lit_str("bearer")) || method.eq(lit_str("header"))))
                return failure("invalid Consumer ID, credential ID, or key method\n");
            if (!contains_id(base, consumers, consumer_id, true))
                return failure("Consumer does not exist in registry snapshot\n");
        }
        if (contains_id(base, credentials, credential_id, true))
            return failure("credential ID already exists in registry snapshot\n");

        OutputPair outputs;
        if (!output_pair(
                argv[kRotateKeyVerifier ? 5 : 6], argv[kRotateKeyVerifier ? 6 : 7], outputs))
            return failure(
                "outputs must be distinct new files in the same owned private directory\n");

        GeneratedSecret secret;
        if (!secret.generate()) return failure("operating-system random key generation failed\n");
        SensitiveHashText digest;
        u32 digest_length = 0;
        if (!hash_hex(HashAlgorithm::Sha256,
                      {secret.hex, sizeof(secret.hex)},
                      {},
                      false,
                      digest.bytes,
                      digest_length) ||
            digest_length != 64)
            return failure("cannot hash generated key for verifier snapshot\n");

        Buffer change_bytes;
        json::Writer change_output{change_bytes.data, json::kMaxBytes};
        if (kRotateKeyVerifier) {
            if (!rotate_key_change(
                    base, source, credential_id, {digest.bytes, digest_length}, change_output))
                return failure("cannot encode rotated verifier snapshot\n");
        } else {
            change_output.text(lit_str("{\"consumers\":[],\"credentials\":[{\"id\":"));
            if (!json::quote(credential_id, change_output))
                return failure("cannot encode verifier snapshot\n");
            change_output.text(lit_str(",\"consumerId\":"));
            if (!json::quote(consumer_id, change_output))
                return failure("cannot encode verifier snapshot\n");
            change_output.text(lit_str(",\"method\":\""));
            change_output.text(method);
            change_output.text(lit_str("\",\"secretSha256\":\""));
            change_output.text({digest.bytes, digest_length});
            change_output.text(
                lit_str("\",\"enabled\":true}],\"removeConsumers\":[],\"removeCredentials\":[]}"));
        }
        if (!change_output.ok) return failure("verifier snapshot change exceeds capacity\n");
        SensitiveDocument patch;
        if (!patch.parse({change_bytes.data, change_output.len}))
            return failure("cannot encode verifier snapshot\n");
        Buffer result;
        json::Writer snapshot{result.data, json::kMaxBytes};
        if (!apply(base, patch, snapshot))
            return failure("verifier snapshot exceeds supported capacity\n");
        SensitiveDocument checked;
        if (!consumer_registry_valid(checked, {result.data, snapshot.len}))
            return failure("generated verifier snapshot is invalid\n");

        const PublishAtResult key_result = publish_at(
            outputs.key.directory, outputs.key.basename, {secret.hex, sizeof(secret.hex)});
        if (key_result != PublishAtResult::Published)
            return failure(key_result == PublishAtResult::Uncertain
                               ? "key output or private temporary may exist; snapshot was not "
                                 "published; inspect the directory before retrying\n"
                               : "key output was not published; snapshot was not published\n");
        const PublishAtResult snapshot_result = publish_at(
            outputs.snapshot.directory, outputs.snapshot.basename, {result.data, snapshot.len});
        if (snapshot_result != PublishAtResult::Published)
            return failure(
                snapshot_result == PublishAtResult::Uncertain
                    ? "key output was published and snapshot output may exist or publication "
                      "durability may be uncertain; inspect both outputs before retrying\n"
                    : "key output was published but snapshot output was not; inspect both outputs "
                      "before retrying\n");
        return 0;
    }
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
