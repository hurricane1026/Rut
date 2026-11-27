#include "rut/runtime/http_cache.h"

#include "rut/common/checked_arithmetic.h"
#include "rut/common/http_header_validation.h"
#include "rut/common/range_int.h"
#include "rut/runtime/format_integer.h"
#include "rut/runtime/http_parser.h"

#include <time.h>

namespace rut {
namespace {

constexpr i64 kMaxBufferedResponse = i64{HttpCachePolicy::kMaxResponse} - 256;

[[nodiscard]] u8 ascii_lower(char byte) {
    const u8 c = __builtin_bit_cast(u8, byte);
    if (c < 'A' || c > 'Z') return c;
    const auto lower = range_int(c) + range_int<'a' - 'A', 'a' - 'A' + 1>{};
    return lower.min(range_int<UINT8_MAX, i64{UINT8_MAX} + 1>{}).to<u8>();
}

[[nodiscard]] bool valid_name(Str name) {
    if (!name.len) return false;
    for (u32 i = 0; i < name.len; ++i)
        if (!is_http_tchar(__builtin_bit_cast(u8, name.ptr[i]))) return false;
    return true;
}
[[nodiscard]] bool eq(Str value, const char* text, u32 length) {
    return http_header_name_eq_ci(value.ptr, value.len, text, length);
}
[[nodiscard]] Str trim(Str text) {
    while (text.len && (*text.ptr == ' ' || *text.ptr == '\t')) {
        ++text.ptr;
        --text.len;
    }
    while (text.len) {
        const char last = text.ptr[i64{text.len} - 1];
        if (last != ' ' && last != '\t') break;
        --text.len;
    }
    return text;
}
[[nodiscard]] bool decimal(Str text, u32& value) {
    text = trim(text);
    if (text.len >= 2 && text.ptr[0] == '"' && text.ptr[i64{text.len} - 1] == '"') {
        ++text.ptr;
        --text.len;
        --text.len;
    }
    if (!text.len) return false;
    u32 result = 0;
    constexpr range_int<UINT32_MAX, i64{UINT32_MAX} + 1> kMax{};
    for (u32 i = 0; i < text.len; ++i) {
        const char byte = text.ptr[i];
        if (byte < '0' || byte > '9') return false;
        static_assert('0' == 0x30 && '9' == 0x39);
        const auto digit = bounded_remainder<16>(__builtin_bit_cast(u8, byte));
        result = (range_int(result).scaled_by<10>() + digit).min(kMax).to<u32>();
    }
    value = result;
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
[[nodiscard]] bool controls(Str text, Controls& out, bool response) {
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
        const auto start = range_int(begin);
        const auto count = (range_int(end) - start).max(range_int<0, 1>{});
        const Str item = trim({text.ptr + start.index(), count.to<u32>()});
        if (!item.len) return false;
        u32 separator = 0;
        while (separator < item.len && item.ptr[separator] != '=') ++separator;
        const Str name = trim({item.ptr, separator});
        if (!valid_name(name)) return false;
        const bool valued = separator < item.len;
        const auto value_start = range_int(separator) + range_int<1, 2>{};
        const auto value_length = (range_int(item.len) - value_start).max(range_int<0, 1>{});
        const Str value =
            valued ? trim({item.ptr + value_start.index(), value_length.to<u32>()}) : Str{};
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
        begin = end;
        ++begin;
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
[[nodiscard]] bool token_list(Str text, bool vary) {
    u32 begin = 0;
    while (begin < text.len) {
        u32 end = begin;
        while (end < text.len && text.ptr[end] != ',') ++end;
        const auto start = range_int(begin);
        const auto count = (range_int(end) - start).max(range_int<0, 1>{});
        const Str name = trim({text.ptr + start.index(), count.to<u32>()});
        if (!valid_name(name)) return false;
        if (vary) {
            if (eq(name, "*", 1) || ignored_key_header(name) || hop_header(name)) return false;
        } else if (!eq(name, "close", 5) && !eq(name, "keep-alive", 10))
            return false;
        if (end == text.len) return true;
        begin = end;
        ++begin;
    }
    return false;
}
u64 hash_bytes(u64 hash, const void* bytes, u32 size) {
    const auto* data = static_cast<const u8*>(bytes);
    for (u32 i = 0; i < size; ++i) hash = (hash ^ data[i]) * 1099511628211ull;
    return hash;
}
[[nodiscard]] bool append(HttpCachePolicy::Key& key, const void* bytes, u32 size) {
    const auto start = range_int(key.len);
    const auto end = start + range_int(size);
    if (end.value() > HttpCachePolicy::kMaxKey) return false;
    __builtin_memcpy(key.bytes + start.index(), bytes, size);
    constexpr i64 kMaxKey = HttpCachePolicy::kMaxKey;
    key.len = end.min(range_int<kMaxKey, kMaxKey + 1>{}).to<u32>();
    return true;
}
// IMF-fixdate only. Unsupported/invalid date syntax is a cache bypass, never a
// guess at freshness. No locale, timezone configuration or wall-clock mutation.
bool http_date(Str value, i64* seconds) {
    if (value.len != 29 || value.ptr[3] != ',' || value.ptr[4] != ' ' || value.ptr[7] != ' ' ||
        value.ptr[11] != ' ' || value.ptr[16] != ' ' || value.ptr[19] != ':' ||
        value.ptr[22] != ':' || value.ptr[25] != ' ' || !Str{value.ptr + 26, 3}.eq(lit_str("GMT")))
        return false;
    const char* p = value.ptr;
    auto number = [&](u32 start, u32 count, u32& result) {
        result = 0;
        for (u32 i = 0; i < count; ++i) {
            const char c = p[static_cast<u32>(static_cast<i64>(start) + static_cast<i64>(i))];
            if (c < '0' || c > '9') return false;
            result = static_cast<u32>(static_cast<i64>(result) * 10 + static_cast<i64>(c) -
                                      static_cast<i64>('0'));
        }
        return true;
    };
    u32 day, year, hour, minute, second;
    if (!number(5, 2, day) || !number(12, 4, year) || !number(17, 2, hour) ||
        !number(20, 2, minute) || !number(23, 2, second) || year < 1970 || hour > 23 ||
        minute > 59 || second > 59)
        return false;
    constexpr char kMonths[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    constexpr i32 kDays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    u32 month = 0;
    while (month < 12 &&
           !Str{p + static_cast<i64>(8), 3}.eq({kMonths + static_cast<i64>(month) * 3, 3}))
        ++month;
    if (month == 12) return false;
    const bool kLeap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    if (day == 0 || static_cast<i64>(day) > static_cast<i64>(kDays[month]) +
                                                static_cast<i64>(month == 1 && kLeap ? 1u : 0u))
        return false;
    constexpr auto kEpochYear = range_int<1970, 1971>::constant<1970>();
    constexpr auto kOne = range_int<1, 2>::constant<1>();
    auto leap_years = [](u32 y) {
        return range_int(y / 4) - range_int(y / 100) + range_int(y / 400);
    };
    const auto last_year = range_int(year) - kOne;
    const auto year_days = (range_int(year) - kEpochYear).scaled_by<365>();
    const auto leap_days =
        leap_years(last_year.max(range_int<0, 1>{}).to<u32>()) - leap_years(1969u);
    i32 days_in_year = static_cast<i32>(day) - 1;
    for (i32 i = 0; i < static_cast<i32>(month); ++i)
        days_in_year += kDays[i] + (i == 1 && kLeap ? 1 : 0);
    const auto days = year_days + leap_days + range_int(days_in_year);
    constexpr char kWeekdays[] = "SunMonTueWedThuFriSat";
    if (!Str{p, 3}.eq({kWeekdays + ((days.value() + 4) % 7) * 3, 3})) return false;
    *seconds = (days.scaled_by<86400>() + range_int(hour).scaled_by<3600>() +
                range_int(minute).scaled_by<60>() + range_int(second))
                   .value();
    return true;
}
struct ResponseInfo {
    ParsedResponse parsed;
    u32 header_end = 0;
    u64 remaining_us = 0;
    u64 age_us = 0;
};
[[nodiscard]] bool response_info(
    const u8* wire, u32 length, u32 cap, u64 wall, u64 delay, ResponseInfo& info) {
    HttpResponseParser parser;
    parser.reset();
    info.parsed.reset();
    auto& response = info.parsed;
    if (parser.parse(wire, length, &response) != ParseStatus::Complete ||
        response.status_code != 200 || response.headers_truncated || response.chunked ||
        !response.has_content_length || response.content_length_count != 1 ||
        (range_int(parser.header_end) + range_int(response.content_length)).value() >
            kMaxBufferedResponse)
        return false;
    info.header_end = parser.header_end;
    Controls policy;
    u32 age = 0;
    bool age_seen = false, date_seen = false, expires_seen = false;
    i64 date = 0, expires = 0;
    for (u32 i = 0; i < response.header_count; ++i) {
        const auto& header = response.headers[i];
        const Str name = header.name;
        if (!valid_name(name)) return false;
        for (u32 j = 0; j < header.value.len; ++j) {
            const u8 c = __builtin_bit_cast(u8, header.value.ptr[j]);
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
            if (date_seen || !http_date(header.value, &date)) return false;
            date_seen = true;
        } else if (eq(name, "expires", 7)) {
            if (expires_seen || !http_date(header.value, &expires)) return false;
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
        lifetime = expires > date ? static_cast<u64>(expires - date) : 0;
    const u32 ttl = lifetime > cap ? cap : static_cast<u32>(lifetime);
    const u64 kLifetimeUs = range_int(ttl).scaled_by<1'000'000>().to_u64();
    const u64 kDateUs = static_cast<u64>(date) * 1000000;
    u64 kApparent = 0;
    if (wall > kDateUs && sub_overflow(wall, kDateUs, &kApparent)) return false;
    const u64 age_us = range_int(age).scaled_by<1'000'000>().to_u64();
    u64 max_delay = 0;
    if (sub_overflow(~u64{0}, age_us, &max_delay) || delay > max_delay) return false;
    u64 kAge = 0;
    if (add_overflow(age_us, delay, &kAge)) return false;
    const u64 kInitial = kApparent > kAge ? kApparent : kAge;
    if (sub_overflow(kLifetimeUs, kInitial, &info.remaining_us) || info.remaining_us == 0)
        return false;
    info.age_us = kInitial;
    return true;
}
[[nodiscard]] bool copy_response(const HttpCacheStorage::Record& entry,
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
        response.content_length !=
            (range_int(entry.response_len) - range_int(parser.header_end)).value())
        return false;
    auto add = [&](const void* p, u32 n) {
        const auto start = range_int(written);
        const auto end = start + range_int(n);
        if (end.value() > capacity) return false;
        __builtin_memcpy(out + start.index(), p, n);
        written = end.min(range_int(capacity)).to<u32>();
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
    u64 elapsed = 0;
    if (now >= entry.stored_us && sub_overflow(now, entry.stored_us, &elapsed)) return false;
    u64 age_total = 0;
    if (add_overflow(entry.initial_age_us, elapsed, &age_total)) return false;
    const u64 kAge = age_total / 1000000;
    char digits[20];
    u32 count = 0;
    u64 value = kAge;
    do {
        digits[count++] = last_decimal_digit(value);
        value /= 10;
    } while (value);
    if (!add("Age: ", 5)) return false;
    for (u32 i = count; i > 0; --i)
        if (!add(digits + i64{i} - 1, 1)) return false;
    const Str connection = keep_alive ? lit_str("\r\nConnection: keep-alive\r\n\r\n")
                                      : lit_str("\r\nConnection: close\r\n\r\n");
    return add(connection.ptr, connection.len) &&
           add(entry.response + range_int(parser.header_end).index(), response.content_length);
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
        const u8 c = ascii_lower(host.ptr[i]);
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
            const u8 c = ascii_lower(header.name.ptr[j]);
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
    u64 kElapsed = ~u64{0};
    if (now_us >= record.stored_us && sub_overflow(now_us, record.stored_us, &kElapsed))
        return false;
    u64 kAgeUs = ~u64{0};
    u64 max_age = 0;
    if (sub_overflow(~u64{0}, record.initial_age_us, &max_age)) return false;
    if (kElapsed <= max_age && add_overflow(kElapsed, record.initial_age_us, &kAgeUs)) return false;
    const bool kFresh =
        now_us < record.expires_us && now_us >= record.stored_us &&
        kAgeUs <= range_int(key.max_age).scaled_by<1'000'000>().to_u64() &&
        key.min_fresh <= kMaxTtl &&
        range_int(key.min_fresh).scaled_by<1'000'000>().to_u64() < ([&] {
            u64 remaining = 0;
            return sub_overflow(record.expires_us, now_us, &remaining) ? 0 : remaining;
        }());
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
        !info.parsed.has_content_length || info.parsed.content_length_count != 1)
        return false;
    const auto response_size = range_int(parser.header_end) + range_int(info.parsed.content_length);
    if (response_size.value() > kMaxBufferedResponse) return false;
    total =
        response_size.min(range_int<kMaxBufferedResponse, kMaxBufferedResponse + 1>{}).to<u32>();
    return true;
}
bool HttpCachePolicy::prepare_record(
    const Fill& fill, const u8* response, u32 length, u64 now_us, u64 wall_us, Record& record) {
    if (!response || length > kMaxResponse || now_us < fill.started_us) return false;
    u64 kElapsed = 0;
    if (sub_overflow(now_us, fill.started_us, &kElapsed)) return false;
    ResponseInfo info;
    if (!response_info(response, length, fill.ttl, wall_us, kElapsed, info) ||
        length != (range_int(info.header_end) + range_int(info.parsed.content_length)).value())
        return false;
    const u64 kRemainingUs = info.remaining_us;
    u64 max_remaining = 0;
    if (sub_overflow(~u64{0}, kRemainingUs, &max_remaining) || now_us > max_remaining) return false;
    u64 expires_us = 0;
    if (add_overflow(now_us, kRemainingUs, &expires_us)) return false;
    record = {response, length, now_us, expires_us, info.age_us};
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
               ? ([&] {
                     u64 whole = 0;
                     u64 fractional = static_cast<u64>(now.tv_nsec) / 1000;
                     if (mul_overflow(static_cast<u64>(now.tv_sec), u64{1000000}, &whole) ||
                         add_overflow(whole, fractional, &whole))
                         return u64{0};
                     return whole;
                 }())
               : 0;
}
}  // namespace rut
