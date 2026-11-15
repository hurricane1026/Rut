#include "rut/runtime/consumer_registry.h"

#include "rut/runtime/auth.h"
#include "rut/runtime/crypto_c.h"

namespace rut {
namespace {
constexpr u32 kMaxConsumers = 32;
constexpr u32 kMaxCredentials = 64;
struct Consumer {
    u32 id = json::kNone;
    u32 groups = json::kNone;
    bool enabled = false;
};
struct Credential {
    u32 id = json::kNone;
    u32 method = json::kNone;
    u32 secret = json::kNone;
    u32 owner = 0;
    bool enabled = false;
};
struct Registry {
    Consumer consumers[kMaxConsumers]{};
    Credential credentials[kMaxCredentials]{};
    u32 consumer_count = 0;
    u32 credential_count = 0;
};
u32 field(json::Document& doc, u32 object, Str name) {
    if (object >= doc.count || doc.nodes[object].kind != json::Kind::Object) return json::kNone;
    for (u32 n = doc.nodes[object].child; n != json::kNone; n = doc.nodes[n].next) {
        json::Writer text{doc.scratch};
        if (!doc.string(doc.nodes[n].key, text)) return json::kNone;
        if (name.eq({text.data, text.len})) return n;
    }
    return json::kNone;
}
bool members(json::Document& doc, u32 object, u32 count) {
    if (object >= doc.count || doc.nodes[object].kind != json::Kind::Object) return false;
    u32 found = 0;
    for (u32 n = doc.nodes[object].child; n != json::kNone; n = doc.nodes[n].next) ++found;
    return found == count;
}
Str text(json::Document& doc, u32 node, char* bytes, u32 capacity) {
    json::Writer output{bytes, capacity};
    return doc.string(node, output) && output.ok ? Str{bytes, output.len} : Str{};
}
bool label(json::Document& doc, u32 node, u32 limit) {
    const Str kText = text(doc, node, doc.scratch, limit);
    if (!kText.len) return false;
    for (u32 i = 0; i < kText.len; ++i)
        if (static_cast<u8>(kText.ptr[i]) < 0x21 || static_cast<u8>(kText.ptr[i]) > 0x7e)
            return false;
    return true;
}
bool same(json::Document& doc, u32 a, u32 b) {
    const Str kLeft = text(doc, a, doc.scratch, json::kMaxBytes);
    const Str kRight = text(doc, b, doc.other, json::kMaxBytes);
    return kLeft.ptr && kRight.ptr && kLeft.eq(kRight);
}
bool enabled(json::Document& doc, u32 node, bool& value) {
    if (node >= doc.count || doc.nodes[node].kind != json::Kind::Boolean) return false;
    value = doc.raw(node).eq(lit_str("true"));
    return true;
}
bool load(json::Document& doc, Str configuration, Registry& result) {
    if (!doc.parse(configuration) || !members(doc, 0, 3)) return false;
    const u32 kVersion = field(doc, 0, lit_str("version"));
    const u32 kConsumers = field(doc, 0, lit_str("consumers"));
    const u32 kCredentials = field(doc, 0, lit_str("credentials"));
    if (kVersion >= doc.count || !doc.raw(kVersion).eq(lit_str("1")) || kConsumers >= doc.count ||
        doc.nodes[kConsumers].kind != json::Kind::Array || kCredentials >= doc.count ||
        doc.nodes[kCredentials].kind != json::Kind::Array)
        return false;
    for (u32 n = doc.nodes[kConsumers].child; n != json::kNone; n = doc.nodes[n].next) {
        if (result.consumer_count == kMaxConsumers || !members(doc, n, 3)) return false;
        auto& consumer = result.consumers[result.consumer_count];
        consumer.id = field(doc, n, lit_str("id"));
        consumer.groups = field(doc, n, lit_str("groups"));
        if (!label(doc, consumer.id, 64) ||
            !enabled(doc, field(doc, n, lit_str("enabled")), consumer.enabled) ||
            consumer.groups >= doc.count || doc.nodes[consumer.groups].kind != json::Kind::Array)
            return false;
        for (u32 i = 0; i < result.consumer_count; ++i)
            if (same(doc, consumer.id, result.consumers[i].id)) return false;
        u32 groups = 0;
        for (u32 group = doc.nodes[consumer.groups].child; group != json::kNone;
             group = doc.nodes[group].next) {
            if (++groups > 16 || !label(doc, group, 128)) return false;
            for (u32 previous = doc.nodes[consumer.groups].child; previous != group;
                 previous = doc.nodes[previous].next)
                if (same(doc, previous, group)) return false;
        }
        ++result.consumer_count;
    }
    for (u32 n = doc.nodes[kCredentials].child; n != json::kNone; n = doc.nodes[n].next) {
        if (result.credential_count == kMaxCredentials || !members(doc, n, 5)) return false;
        auto& credential = result.credentials[result.credential_count];
        credential.id = field(doc, n, lit_str("id"));
        credential.method = field(doc, n, lit_str("method"));
        credential.secret = field(doc, n, lit_str("secret"));
        const u32 kOwner = field(doc, n, lit_str("consumerId"));
        if (!label(doc, credential.id, 64) || !label(doc, kOwner, 64) ||
            !enabled(doc, field(doc, n, lit_str("enabled")), credential.enabled))
            return false;
        bool owner_found = false;
        for (u32 i = 0; i < result.consumer_count; ++i) {
            if (!same(doc, kOwner, result.consumers[i].id)) continue;
            credential.owner = i;
            owner_found = true;
        }
        if (!owner_found) return false;
        char method_bytes[16];
        const Str kMethod = text(doc, credential.method, method_bytes, sizeof(method_bytes));
        const Str kSecret = text(doc, credential.secret, doc.scratch, kMaxBearerKeyBytes);
        if (!kSecret.len || (kMethod.eq(lit_str("basic")) ? !basic_credentials_valid(kSecret)
                             : kMethod.eq(lit_str("bearer")) || kMethod.eq(lit_str("header"))
                                 ? !bearer_key_valid(kSecret)
                             : kMethod.eq(lit_str("mtls")) ? !sha256_hex_format_valid(kSecret)
                                                           : true))
            return false;
        for (u32 i = 0; i < result.credential_count; ++i) {
            const auto& previous = result.credentials[i];
            if (same(doc, previous.id, credential.id) ||
                (same(doc, previous.method, credential.method) &&
                 same(doc, previous.secret, credential.secret)))
                return false;
        }
        ++result.credential_count;
    }
    return true;
}
}  // namespace

bool consumer_registry_valid(json::Document& document, Str configuration) {
    Registry registry;
    return load(document, configuration, registry);
}

static bool authenticate(json::Document& document,
                         Str configuration,
                         Str method,
                         Str presented,
                         bool allow_mtls,
                         json::Writer& output) {
    if (method.eq(lit_str("mtls")) && !allow_mtls) return false;
    Registry registry;
    if (!load(document, configuration, registry) || !presented.ptr || !presented.len) return false;
    u32 selected = json::kNone;
    for (u32 i = 0; i < registry.credential_count; ++i) {
        const auto& credential = registry.credentials[i];
        char method_bytes[16];
        if (!method.eq(text(document, credential.method, method_bytes, sizeof(method_bytes))))
            continue;
        const Str kSecret = text(document, credential.secret, document.scratch, kMaxBearerKeyBytes);
        const bool kMatch =
            method.eq(lit_str("basic"))    ? basic_matches(presented, kSecret)
            : method.eq(lit_str("bearer")) ? bearer_matches(presented, kSecret)
            : method.eq(lit_str("mtls"))
                ? presented.len == kSecret.len &&
                      rut_crypto_equal_v1(reinterpret_cast<const u8*>(presented.ptr),
                                          reinterpret_cast<const u8*>(kSecret.ptr),
                                          kSecret.len)
            : method.eq(lit_str("header"))
                ? presented.len == kSecret.len &&
                      rut_crypto_equal_v1(reinterpret_cast<const u8*>(presented.ptr),
                                          reinterpret_cast<const u8*>(kSecret.ptr),
                                          kSecret.len)
                : false;
        // Evaluate every configured credential. Disabled entries never grant.
        if (kMatch && credential.enabled && registry.consumers[credential.owner].enabled)
            selected = i;
    }
    if (selected == json::kNone) return false;
    const auto& credential = registry.credentials[selected];
    const auto& consumer = registry.consumers[credential.owner];
    output.text(lit_str("{\"consumerId\":"));
    output.text(document.raw(consumer.id));
    output.text(lit_str(",\"credentialId\":"));
    output.text(document.raw(credential.id));
    output.text(lit_str(",\"method\":"));
    output.text(document.raw(credential.method));
    output.text(lit_str(",\"groups\":"));
    output.text(document.raw(consumer.groups));
    output.put('}');
    return output.ok;
}

bool consumer_registry_authenticate(
    json::Document& document, Str configuration, Str method, Str presented, json::Writer& output) {
    return authenticate(document, configuration, method, presented, false, output);
}

bool consumer_registry_authenticate_mtls(json::Document& document,
                                         Str configuration,
                                         Str fingerprint,
                                         json::Writer& output) {
    if (!sha256_hex_format_valid(fingerprint)) return false;
    return authenticate(document, configuration, lit_str("mtls"), fingerprint, true, output);
}
namespace {
i32 field_hex(char byte) {
    if (byte >= '0' && byte <= '9') return byte - '0';
    if (byte >= 'a' && byte <= 'f') return byte - 'a' + 10;
    if (byte >= 'A' && byte <= 'F') return byte - 'A' + 10;
    return -1;
}
bool decode_field(Str raw, char* bytes, u32 capacity, u32& length) {
    length = 0;
    for (u32 i = 0; i < raw.len; ++i) {
        u32 byte = static_cast<u8>(raw.ptr[i]);
        if (byte == '%') {
            if (raw.len - i < 3) return false;
            const i32 high = field_hex(raw.ptr[i + 1]), low = field_hex(raw.ptr[i + 2]);
            if (high < 0 || low < 0) return false;
            byte = static_cast<u32>(high * 16 + low);
            i += 2;
        } else if (byte == '+')
            byte = ' ';
        // ASCII profile rejects controls, NUL and alternate raw delimiters.
        else if (byte == ';' || byte == '#')
            return false;
        if (byte < 32 || byte > 126 || length == capacity) return false;
        bytes[length++] = static_cast<char>(byte);
    }
    return true;
}
}  // namespace
bool consumer_credential_name_valid(Str name) {
    if (!name.ptr || !name.len || name.len > 64) return false;
    for (u32 i = 0; i < name.len; ++i) {
        const char byte = name.ptr[i];
        if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
              (byte >= '0' && byte <= '9') || byte == '_' || byte == '-' || byte == '.'))
            return false;
    }
    return true;
}
bool consumer_registry_authenticate_fields(json::Document& document,
                                           Str configuration,
                                           Str name,
                                           Str input,
                                           bool query,
                                           json::Writer& output) {
    if (!consumer_credential_name_valid(name) || !input.ptr || !input.len || input.len > 4096)
        return false;
    if (query) {
        if (input.ptr[0] != '/') return false;
        u32 separator = input.len;
        for (u32 i = 0; i < input.len; ++i) {
            const auto byte = static_cast<u8>(input.ptr[i]);
            if (byte <= 32 || byte >= 127 || byte == '#') return false;
            if (byte == '?' && separator == input.len) separator = i;
        }
        if (separator == input.len) return false;
        input = {input.ptr + separator + 1, input.len - separator - 1};
    }
    char names[64][64]{};
    u32 lengths[64]{};
    u32 count = 0;
    char credential[512]{};
    u32 credential_length = 0;
    char remaining[4096]{};
    u32 remaining_length = 0;
    for (u32 begin = 0; begin < input.len;) {
        if (count == 64) return false;
        u32 end = begin, equals = input.len;
        while (end < input.len && input.ptr[end] != '&') {
            if (input.ptr[end] == '=' && equals == input.len) equals = end;
            ++end;
        }
        if (equals >= end || equals == begin || end == begin ||
            !decode_field({input.ptr + begin, equals - begin}, names[count], 64, lengths[count]) ||
            !consumer_credential_name_valid({names[count], lengths[count]}))
            return false;
        const Str current{names[count], lengths[count]};
        for (u32 n = 0; n < count; ++n)
            if (current.eq({names[n], lengths[n]})) return false;
        char decoded[4096];
        u32 decoded_length = 0;
        if (!decode_field({input.ptr + equals + 1, end - equals - 1},
                          decoded,
                          sizeof(decoded),
                          decoded_length))
            return false;
        if (current.eq(name)) {
            if (!decoded_length || decoded_length > sizeof(credential)) return false;
            __builtin_memcpy(credential, decoded, decoded_length);
            credential_length = decoded_length;
        } else {
            if (remaining_length) remaining[remaining_length++] = '&';
            __builtin_memcpy(remaining + remaining_length, input.ptr + begin, end - begin);
            remaining_length += end - begin;
        }
        ++count;
        if (end + 1 == input.len) return false;
        begin = end + 1;
    }
    if (!credential_length ||
        !consumer_registry_authenticate(
            document, configuration, lit_str("header"), {credential, credential_length}, output))
        return false;
    // Authentication wrote one complete identity object. Extend only on success.
    --output.len;
    output.text(lit_str(",\"remaining\":"));
    if (!json::quote({remaining, remaining_length}, output)) return false;
    output.put('}');
    return output.ok;
}
}  // namespace rut
