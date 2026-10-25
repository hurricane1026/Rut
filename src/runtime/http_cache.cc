#include "rut/runtime/http_cache.h"

#include "rut/common/http_header_validation.h"
#include "rut/runtime/http_parser.h"

#include <time.h>

namespace rut {
namespace {

bool valid_name(Str name) {
    if (!name.len) return false;
    for (u32 i = 0; i < name.len; ++i)
        if (!is_http_tchar(static_cast<u8>(name.ptr[i]))) return false;
    return true;
}
bool eq(Str value, const char* text, u32 length) {
    return http_header_name_eq_ci(value.ptr, value.len, text, length);
}
Str trim(Str text) {
    while (text.len && (*text.ptr == ' ' || *text.ptr == '\t')) {
        ++text.ptr;
        --text.len;
    }
    while (text.len && (text.ptr[text.len - 1] == ' ' || text.ptr[text.len - 1] == '\t'))
        --text.len;
    return text;
}
bool decimal(Str text, u32& value) {
    text = trim(text);
    if (text.len >= 2 && text.ptr[0] == '"' && text.ptr[text.len - 1] == '"')
        text = {text.ptr + 1, text.len - 2};
    if (!text.len) return false;
    u64 result = 0;
    for (u32 i = 0; i < text.len; ++i) {
        if (text.ptr[i] < '0' || text.ptr[i] > '9') return false;
        result = result * 10 + static_cast<u32>(text.ptr[i] - '0');
        if (result > 0xffffffffu) result = 0xffffffffu;
    }
    value = static_cast<u32>(result);
    return true;
}
struct Controls {
    bool blocked = false;
    bool only_cached = false;
    bool max_seen = false;
    bool shared_seen = false;
    bool min_seen = false;
    u32 max_age = 0xffffffffu;
    u32 shared_age = 0xffffffffu;
    u32 min_fresh = 0;
};
bool controls(Str text, Controls& out, bool response) {
    u32 begin = 0;
    while (begin < text.len) {
        u32 end = begin;
        bool quoted = false;
        for (; end < text.len; ++end) {
            if (text.ptr[end] == '"') quoted = !quoted;
            if (!quoted && text.ptr[end] == ',') break;
            if (text.ptr[end] == '\\') return false;  // conservative on escaped extension values
        }
        if (quoted) return false;
        Str item = trim({text.ptr + begin, end - begin});
        if (!item.len) return false;
        u32 separator = 0;
        while (separator < item.len && item.ptr[separator] != '=') ++separator;
        const Str name = trim({item.ptr, separator});
        if (!valid_name(name)) return false;
        const bool valued = separator < item.len;
        const Str value =
            valued ? trim({item.ptr + separator + 1, item.len - separator - 1}) : Str{};
        if (eq(name, "no-store", 8) || eq(name, "no-cache", 8) ||
            (response && eq(name, "private", 7)))
            out.blocked = true;
        if (!response && eq(name, "only-if-cached", 14)) {
            if (valued) return false;
            out.only_cached = true;
        }
        u32* target = nullptr;
        bool* seen = nullptr;
        if (eq(name, "max-age", 7)) {
            target = &out.max_age;
            seen = &out.max_seen;
        } else if (response && eq(name, "s-maxage", 8)) {
            target = &out.shared_age;
            seen = &out.shared_seen;
        } else if (!response && eq(name, "min-fresh", 9)) {
            target = &out.min_fresh;
            seen = &out.min_seen;
        }
        if (target) {
            if (!valued || *seen || !decimal(value, *target)) return false;
            *seen = true;
        }
        if (end == text.len) break;
        begin = end + 1;
        if (begin == text.len) return false;
    }
    return true;
}
bool ignored_key_header(Str name) {
    return eq(name, "cache-control", 13) || eq(name, "pragma", 6) || eq(name, "connection", 10) ||
           eq(name, "proxy-connection", 16) || eq(name, "keep-alive", 10);
}
bool hop_header(Str name) {
    return eq(name, "connection", 10) || eq(name, "proxy-connection", 16) ||
           eq(name, "keep-alive", 10) || eq(name, "transfer-encoding", 17) || eq(name, "te", 2) ||
           eq(name, "trailer", 7) || eq(name, "upgrade", 7);
}
bool token_list(Str text, bool vary) {
    u32 begin = 0;
    while (begin < text.len) {
        u32 end = begin;
        while (end < text.len && text.ptr[end] != ',') ++end;
        const Str name = trim({text.ptr + begin, end - begin});
        if (!valid_name(name)) return false;
        if (vary) {
            if (eq(name, "*", 1) || ignored_key_header(name) || hop_header(name)) return false;
        } else if (!eq(name, "close", 5) && !eq(name, "keep-alive", 10))
            return false;
        if (end == text.len) return true;
        begin = end + 1;
    }
    return false;
}
u64 hash_bytes(u64 hash, const void* bytes, u32 size) {
    const auto* data = static_cast<const u8*>(bytes);
    for (u32 i = 0; i < size; ++i) hash = (hash ^ data[i]) * 1099511628211ull;
    return hash;
}
bool append(HttpCachePolicy::Key& key, const void* bytes, u32 size) {
    if (size > HttpCachePolicy::kMaxKey - key.len) return false;
    __builtin_memcpy(key.bytes + key.len, bytes, size);
    key.len += size;
    return true;
}
// IMF-fixdate only. Unsupported/invalid date syntax is a cache bypass, never a
// guess at freshness. No locale, timezone configuration or wall-clock mutation.
bool http_date(Str value, u64& seconds) {
    if (value.len != 29 || value.ptr[3] != ',' || value.ptr[4] != ' ' || value.ptr[7] != ' ' ||
        value.ptr[11] != ' ' || value.ptr[16] != ' ' || value.ptr[19] != ':' ||
        value.ptr[22] != ':' || value.ptr[25] != ' ' || !Str{value.ptr + 26, 3}.eq(lit_str("GMT")))
        return false;
    const char* p = value.ptr;
    auto number = [&](u32 start, u32 count, u32& result) {
        result = 0;
        for (u32 i = 0; i < count; ++i) {
            const char c = p[start + i];
            if (c < '0' || c > '9') return false;
            result = result * 10 + static_cast<u32>(c - '0');
        }
        return true;
    };
    u32 day, year, hour, minute, second;
    if (!number(5, 2, day) || !number(12, 4, year) || !number(17, 2, hour) ||
        !number(20, 2, minute) || !number(23, 2, second) || year < 1970 || hour > 23 ||
        minute > 59 || second > 59)
        return false;
    constexpr char kMonths[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    constexpr u32 kDays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    u32 month = 0;
    while (month < 12 && !Str{p + 8, 3}.eq({kMonths + static_cast<u64>(month) * 3, 3})) ++month;
    if (month == 12) return false;
    const bool kLeap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    if (day == 0 || day > kDays[month] + (month == 1 && kLeap ? 1u : 0u)) return false;
    auto leap_years = [](u32 y) -> u64 { return y / 4 - y / 100 + y / 400; };
    u64 days = static_cast<u64>(year - 1970) * 365 + leap_years(year - 1) - leap_years(1969);
    for (u32 i = 0; i < month; ++i) days += kDays[i] + (i == 1 && kLeap ? 1u : 0u);
    days += day - 1;
    constexpr char kWeekdays[] = "SunMonTueWedThuFriSat";
    if (!Str{p, 3}.eq({kWeekdays + ((days + 4) % 7) * 3, 3})) return false;
    seconds = days * 86400 + static_cast<u64>(hour) * 3600 + static_cast<u64>(minute) * 60 + second;
    return true;
}
struct ResponseInfo {
    ParsedResponse parsed;
    u32 header_end = 0;
    u32 ttl = 0;
    u64 age_us = 0;
};
bool response_info(const u8* wire, u32 length, u32 cap, u64 wall, u64 delay, ResponseInfo& info) {
    HttpResponseParser parser;
    parser.reset();
    info.parsed.reset();
    auto& response = info.parsed;
    if (parser.parse(wire, length, &response) != ParseStatus::Complete ||
        response.status_code != 200 || response.headers_truncated || response.chunked ||
        !response.has_content_length || response.content_length_count != 1 ||
        response.content_length > HttpCachePolicy::kMaxResponse - 256 ||
        parser.header_end > HttpCachePolicy::kMaxResponse - 256 - response.content_length)
        return false;
    info.header_end = parser.header_end;
    Controls policy;
    u32 age = 0;
    bool age_seen = false, date_seen = false, expires_seen = false;
    u64 date = 0, expires = 0;
    for (u32 i = 0; i < response.header_count; ++i) {
        const auto& header = response.headers[i];
        const Str name = header.name;
        if (!valid_name(name)) return false;
        for (u32 j = 0; j < header.value.len; ++j) {
            const u8 c = static_cast<u8>(header.value.ptr[j]);
            if ((c < 0x20 && c != '\t') || c == 0x7f) return false;
        }
        if (eq(name, "cache-control", 13)) {
            if (!controls(header.value, policy, true)) return false;
        } else if (eq(name, "vary", 4)) {
            if (!token_list(header.value, true)) return false;
        } else if (eq(name, "connection", 10)) {
            if (!token_list(header.value, false)) return false;
        } else if (eq(name, "age", 3)) {
            if (age_seen || !decimal(header.value, age)) return false;
            age_seen = true;
        } else if (eq(name, "date", 4)) {
            if (date_seen || !http_date(header.value, date)) return false;
            date_seen = true;
        } else if (eq(name, "expires", 7)) {
            if (expires_seen || !http_date(header.value, expires)) return false;
            expires_seen = true;
        } else if (eq(name, "set-cookie", 10) || eq(name, "set-cookie2", 11) ||
                   eq(name, "content-range", 13) || eq(name, "trailer", 7) ||
                   eq(name, "transfer-encoding", 17) || eq(name, "upgrade", 7))
            return false;
    }
    // A Date is necessary to account for upstream age without synthesizing
    // origin metadata. Date-less responses continue through the ordinary proxy.
    if (policy.blocked || !date_seen || wall == 0 || cap == 0 || cap > HttpCachePolicy::kMaxTtl)
        return false;
    u64 lifetime = cap;
    if (policy.shared_seen)
        lifetime = policy.shared_age;
    else if (policy.max_seen)
        lifetime = policy.max_age;
    else if (expires_seen)
        lifetime = expires > date ? expires - date : 0;
    if (lifetime > cap) lifetime = cap;
    const u64 kDateUs = date * 1000000;
    const u64 kApparent = wall > kDateUs ? wall - kDateUs : 0;
    if (delay > ~u64{0} - static_cast<u64>(age) * 1000000) return false;
    const u64 kAge = static_cast<u64>(age) * 1000000 + delay;
    const u64 kInitial = kApparent > kAge ? kApparent : kAge;
    if (kInitial >= lifetime * 1000000) return false;
    info.ttl = static_cast<u32>(lifetime);
    info.age_us = kInitial;
    return true;
}
bool copy_response(const HttpCacheStorage::Record& entry,
                   u64 now,
                   bool keep_alive,
                   bool http10,
                   u8* out,
                   u32 capacity,
                   u32& written) {
    written = 0;
    if (!entry.response || entry.response_len > HttpCacheStorage::kMaxResponse) return false;
    HttpResponseParser parser;
    ParsedResponse response;
    parser.reset();
    response.reset();
    if (parser.parse(entry.response, entry.response_len, &response) != ParseStatus::Complete ||
        response.status_code != 200 || response.headers_truncated || response.chunked ||
        !response.has_content_length || response.content_length_count != 1 ||
        parser.header_end > entry.response_len ||
        response.content_length != entry.response_len - parser.header_end)
        return false;
    auto add = [&](const void* p, u32 n) {
        if (n > capacity - written) return false;
        __builtin_memcpy(out + written, p, n);
        written += n;
        return true;
    };
    if (!add(http10 ? "HTTP/1.0 200 OK\r\n" : "HTTP/1.1 200 OK\r\n", 17)) return false;
    for (u32 i = 0; i < response.header_count; ++i) {
        const auto& header = response.headers[i];
        if (hop_header(header.name) || eq(header.name, "age", 3)) continue;
        if (!add(header.name.ptr, header.name.len) || !add(": ", 2) ||
            !add(header.value.ptr, header.value.len) || !add("\r\n", 2))
            return false;
    }
    const u64 kAge = (entry.initial_age_us + (now - entry.stored_us)) / 1000000;
    char digits[20];
    u32 count = 0;
    u64 value = kAge;
    do {
        digits[count++] = static_cast<char>('0' + value % 10);
        value /= 10;
    } while (value);
    if (!add("Age: ", 5)) return false;
    for (u32 i = count; i > 0; --i)
        if (!add(digits + i - 1, 1)) return false;
    const Str connection = keep_alive ? lit_str("\r\nConnection: keep-alive\r\n\r\n")
                                      : lit_str("\r\nConnection: close\r\n\r\n");
    return add(connection.ptr, connection.len) &&
           add(entry.response + parser.header_end, response.content_length);
}
}  // namespace

bool HttpCachePolicy::make_key(
    const u8* request, u32 length, u64 config, u32 route, bool tls, u32 peer, Key& key) {
    key = {};
    key.config = config;
    HttpParser parser;
    ParsedRequest req;
    parser.reset();
    req.reset();
    if (!request || config == 0 || parser.parse(request, length, &req) != ParseStatus::Complete ||
        req.header_count >= kMaxHeaders)
        return false;
    key.http10 = req.version == HttpVersion::Http10;
    Str host{};
    u32 hosts = 0;
    Controls policy;
    bool blocked = req.method != HttpMethod::GET || req.chunked || req.content_length_count > 1 ||
                   (req.has_content_length && req.content_length != 0);
    key.unsafe = req.method != HttpMethod::GET && req.method != HttpMethod::HEAD &&
                 req.method != HttpMethod::OPTIONS && req.method != HttpMethod::TRACE;
    for (u32 i = 0; i < req.header_count; ++i) {
        const auto& header = req.headers[i];
        const Str name = header.name;
        if (eq(name, "host", 4)) {
            host = header.value;
            ++hosts;
        }
        if (eq(name, "authorization", 13) || eq(name, "proxy-authorization", 19) ||
            eq(name, "x-api-key", 9) || eq(name, "cookie", 6) || eq(name, "cookie2", 7) ||
            eq(name, "range", 5) || eq(name, "upgrade", 7) || eq(name, "transfer-encoding", 17) ||
            (name.len >= 3 && eq({name.ptr, 3}, "if-", 3)))
            blocked = true;
        if (eq(name, "pragma", 6)) blocked = true;
        if (eq(name, "cache-control", 13) && !controls(header.value, policy, false)) blocked = true;
    }
    key.only_cached = policy.only_cached;
    key.max_age = policy.max_age;
    key.min_fresh = policy.min_fresh;
    if (hosts != 1 || host.len == 0 || req.path.len == 0 || req.path.ptr[0] != '/') return false;
    u64 host_hash = hash_bytes(1469598103934665603ull, &tls, sizeof(tls));
    for (u32 i = 0; i < host.len; ++i) {
        u8 c = static_cast<u8>(host.ptr[i]);
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        host_hash = hash_bytes(host_hash, &c, 1);
    }
    key.host = host_hash;
    if (blocked || policy.blocked) return true;
    if (!append(key, &route, sizeof(route)) || !append(key, &req.version, sizeof(req.version)) ||
        !append(key, &tls, sizeof(tls)) || !append(key, &peer, sizeof(peer)) ||
        !append(key, req.path.ptr, req.path.len) || !append(key, "\n", 1))
        return true;
    for (u32 i = 0; i < req.header_count; ++i) {
        const auto& header = req.headers[i];
        if (ignored_key_header(header.name)) continue;
        for (u32 j = 0; j < header.name.len; ++j) {
            u8 c = static_cast<u8>(header.name.ptr[j]);
            if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
            if (!append(key, &c, 1)) return true;
        }
        if (!append(key, ":", 1) || !append(key, header.value.ptr, header.value.len) ||
            !append(key, "\n", 1))
            return true;
    }
    key.hash = hash_bytes(1469598103934665603ull, key.bytes, key.len);
    key.eligible = true;
    return true;
}

bool HttpCachePolicy::read_response(const Key& key,
                                    const Record& record,
                                    u64 now_us,
                                    bool keep_alive,
                                    u8* output,
                                    u32 capacity,
                                    u32& written) {
    const u64 kElapsed = now_us >= record.stored_us ? now_us - record.stored_us : ~u64{0};
    const u64 kAgeUs =
        kElapsed <= ~u64{0} - record.initial_age_us ? kElapsed + record.initial_age_us : ~u64{0};
    const bool kFresh = now_us < record.expires_us && now_us >= record.stored_us &&
                        kAgeUs <= static_cast<u64>(key.max_age) * 1000000 &&
                        key.min_fresh <= kMaxTtl &&
                        static_cast<u64>(key.min_fresh) * 1000000 < record.expires_us - now_us;
    return kFresh &&
           copy_response(record, now_us, keep_alive, key.http10, output, capacity, written);
}
bool HttpCachePolicy::response_can_buffer(const u8* response, u32 length, u32& total) {
    ResponseInfo info;
    // Eligibility that does not depend on the live clock; policy is checked at commit.
    HttpResponseParser parser;
    parser.reset();
    info.parsed.reset();
    if (parser.parse(response, length, &info.parsed) != ParseStatus::Complete ||
        info.parsed.status_code != 200 || info.parsed.headers_truncated || info.parsed.chunked ||
        !info.parsed.has_content_length || info.parsed.content_length_count != 1 ||
        info.parsed.content_length > kMaxResponse - 256 ||
        parser.header_end > kMaxResponse - 256 - info.parsed.content_length)
        return false;
    total = parser.header_end + info.parsed.content_length;
    return true;
}
bool HttpCachePolicy::prepare_record(
    const Fill& fill, const u8* response, u32 length, u64 now_us, u64 wall_us, Record& record) {
    if (!response || length > kMaxResponse || now_us < fill.started_us) return false;
    const u64 kElapsed = now_us - fill.started_us;
    ResponseInfo info;
    if (!response_info(response, length, fill.ttl, wall_us, kElapsed, info) ||
        length != info.header_end + info.parsed.content_length)
        return false;
    const u64 kRemainingUs = static_cast<u64>(info.ttl) * 1000000 - info.age_us;
    if (now_us > ~u64{0} - kRemainingUs) return false;
    record = {response, length, now_us, now_us + kRemainingUs, info.age_us};
    return true;
}
HttpCache& local_http_cache() {
    static thread_local HttpCache cache;
    return cache;
}
u64 http_cache_config_identity() {
    static u64 next = 0;
    return __atomic_add_fetch(&next, 1, __ATOMIC_RELAXED);
}
u64 http_cache_wall_us() {
    struct timespec now{};
    return clock_gettime(CLOCK_REALTIME, &now) == 0 && now.tv_sec > 0 && now.tv_nsec >= 0 &&
                   now.tv_nsec < 1000000000 && static_cast<u64>(now.tv_sec) <= ~u64{0} / 1000000
               ? static_cast<u64>(now.tv_sec) * 1000000 + static_cast<u64>(now.tv_nsec) / 1000
               : 0;
}
}  // namespace rut
