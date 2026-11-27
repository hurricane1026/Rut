#include "rut/runtime/access_log.h"

#include "rut/common/integer_conversion.h"
#include "rut/runtime/access_log_host.h"
#include <atomic>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/un.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#include <time.h>
#include <unistd.h>
#include <zstd.h>

namespace rut {

// --- Text formatting helpers (no stdlib) ---

static u64 saturating_mul_u64(u64 value, u64 scale) {
    u64 result = 0;
    return __builtin_mul_overflow(value, scale, &result) ? UINT64_MAX : result;
}

static u64 timespec_to_units(const timespec& ts, u64 scale) {
    if (ts.tv_sec < 0 || ts.tv_nsec < 0) return 0;
    const u64 seconds = static_cast<u64>(ts.tv_sec);
    const u64 fraction = scale == 1'000'000'000ULL ? static_cast<u64>(ts.tv_nsec)
                                                   : static_cast<u64>(ts.tv_nsec) / 1000;
    const u64 whole = saturating_mul_u64(seconds, scale);
    if (whole == UINT64_MAX) return UINT64_MAX;
    u64 result = 0;
    if (__builtin_add_overflow(whole, fraction, &result)) return UINT64_MAX;
    return result;
}

static u64 raw_monotonic_us() {
    struct timespec ts;
#ifdef __APPLE__
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 1;
#else
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts) != 0) return 1;
#endif
    u64 now = timespec_to_units(ts, 1000000);
    return now == 0 ? 1 : now;
}

static thread_local u64 g_last_monotonic_us = raw_monotonic_us();

u64 realtime_us() {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0;
    return timespec_to_units(ts, 1000000);
}

u64 monotonic_us() {
    struct timespec ts;
    // Preserve the nonzero in-flight sentinel even when the monotonic clock fails.
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return g_last_monotonic_us;
    }
    u64 now = timespec_to_units(ts, 1000000);
    if (now == 0) now = 1;
    const u64 result = now < g_last_monotonic_us ? g_last_monotonic_us : now;
    g_last_monotonic_us = result;
    return result;
}

u64 monotonic_ns() {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return saturating_mul_u64(g_last_monotonic_us, 1000ULL);  // best-effort fallback
    }
    return timespec_to_units(ts, 1'000'000'000ULL);
}

static u32 write_u64_dec(char* buf, u64 val) {
    if (val == 0) {
        buf[0] = '0';
        return 1;
    }
    char tmp[20];
    i64 n = 0;
    while (val > 0) {
        tmp[n++] = static_cast<char>('0' + static_cast<i64>(val % 10));
        val /= 10;
    }
    for (i64 i = 0; i < n; i++) buf[i] = tmp[n - 1 - i];
    return static_cast<u32>(n);
}

static u32 copy_str(char* dst, const char* src) {
    i64 n = 0;
    while (src[n]) {
        dst[n] = src[n];
        n++;
    }
    return static_cast<u32>(n);
}

static const char* method_str(u8 m) {
    switch (static_cast<LogHttpMethod>(m)) {
        case LogHttpMethod::Get:
            return "GET";
        case LogHttpMethod::Post:
            return "POST";
        case LogHttpMethod::Put:
            return "PUT";
        case LogHttpMethod::Delete:
            return "DELETE";
        case LogHttpMethod::Patch:
            return "PATCH";
        case LogHttpMethod::Head:
            return "HEAD";
        case LogHttpMethod::Options:
            return "OPTIONS";
        case LogHttpMethod::Connect:
            return "CONNECT";
        case LogHttpMethod::Trace:
            return "TRACE";
        default:
            return "OTHER";
    }
}

// Format ISO8601 timestamp: "YYYY-MM-DDTHH:MM:SS.mmmZ" (24 chars)
static u32 format_timestamp(char* buf, u64 timestamp_us) {
    u64 secs = timestamp_us / 1000000ULL;
    u32 millis = static_cast<u32>((timestamp_us % 1000000ULL) / 1000);

    struct tm tm;
    time_t t = static_cast<time_t>(secs);
    gmtime_r(&t, &tm);

    i64 w = 0;
    u32 year = static_cast<u32>(tm.tm_year + 1900);
    buf[w++] = static_cast<char>('0' + static_cast<i64>(year / 1000));
    buf[w++] = static_cast<char>('0' + static_cast<i64>((year / 100) % 10));
    buf[w++] = static_cast<char>('0' + static_cast<i64>((year / 10) % 10));
    buf[w++] = static_cast<char>('0' + static_cast<i64>(year % 10));
    buf[w++] = '-';
    u32 mon = static_cast<u32>(tm.tm_mon + 1);
    buf[w++] = static_cast<char>('0' + static_cast<i64>(mon / 10));
    buf[w++] = static_cast<char>('0' + static_cast<i64>(mon % 10));
    buf[w++] = '-';
    u32 day = static_cast<u32>(tm.tm_mday);
    buf[w++] = static_cast<char>('0' + static_cast<i64>(day / 10));
    buf[w++] = static_cast<char>('0' + static_cast<i64>(day % 10));
    buf[w++] = 'T';
    u32 hour = static_cast<u32>(tm.tm_hour);
    buf[w++] = static_cast<char>('0' + static_cast<i64>(hour / 10));
    buf[w++] = static_cast<char>('0' + static_cast<i64>(hour % 10));
    buf[w++] = ':';
    u32 min = static_cast<u32>(tm.tm_min);
    buf[w++] = static_cast<char>('0' + static_cast<i64>(min / 10));
    buf[w++] = static_cast<char>('0' + static_cast<i64>(min % 10));
    buf[w++] = ':';
    u32 sec = static_cast<u32>(tm.tm_sec);
    buf[w++] = static_cast<char>('0' + static_cast<i64>(sec / 10));
    buf[w++] = static_cast<char>('0' + static_cast<i64>(sec % 10));
    buf[w++] = '.';
    buf[w++] = static_cast<char>('0' + static_cast<i64>(millis / 100));
    buf[w++] = static_cast<char>('0' + static_cast<i64>((millis / 10) % 10));
    buf[w++] = static_cast<char>('0' + static_cast<i64>(millis % 10));
    buf[w++] = 'Z';
    return static_cast<u32>(w);
}

// Format IPv4 from network byte order.
// Format IPv4 from network byte order.
// Access raw bytes to be endian-safe (works on both LE and BE hosts).
static u32 format_ipv4(char* buf, u32 addr) {
    const auto* bytes = reinterpret_cast<const u8*>(&addr);
    i64 w = 0;
    for (i64 i = 0; i < 4; i++) {
        if (i > 0) buf[w++] = '.';
        u8 octet = bytes[i];
        if (octet >= 100) buf[w++] = static_cast<char>('0' + octet / 100);
        if (octet >= 10) buf[w++] = static_cast<char>('0' + (octet / 10) % 10);
        buf[w++] = static_cast<char>('0' + octet % 10);
    }
    return static_cast<u32>(w);
}

// Format: "2026-03-23T15:30:00.123Z GET /path 200 1234us 256 1024 10.0.0.5 s=3\n"
// Compact, greppable, no quoting needed for simple strict targets. Build the whole line in
// private bounded storage so an invalid/undersized caller cannot observe a partial record.
u32 format_access_log_text(const AccessLogEntry& entry, char* buf, u32 buf_size) {
    static constexpr char kOverLimitPrefix[] = "<request-target-over-limit:";
    static constexpr char kUnavailable[] = "<request-target-unavailable>";
    static constexpr char kInvalid[] = "<request-target-invalid>";
    static constexpr i64 kWorstCaseLine =
        24 + 1 + 7 + 1 + static_cast<i64>(kAccessLogCompleteTargetMax) + 1 + 5u + 1u + 10u + 3u +
        10u + 1u + 10u + 1u + 15u + 1u + 24u + 1u + 10u + 2u + 3u + 3u + 16u + 1u;
    static_assert(kWorstCaseLine <= static_cast<i64>(kAccessLogTextLineCapacity));

    char line[kAccessLogTextLineCapacity];
    i64 w = 0;

    w += static_cast<i64>(format_timestamp(line + w, entry.timestamp_us));
    line[w++] = ' ';
    w += static_cast<i64>(copy_str(line + w, method_str(entry.method)));
    line[w++] = ' ';

    const auto invalid_target = [&] { w += static_cast<i64>(copy_str(line + w, kInvalid)); };
    switch (entry.target_state) {
        case AccessLogTargetState::LegacyNullTerminated: {
            if (entry.target_length != 0u) {
                invalid_target();
                break;
            }
            i64 path_len = 0;
            while (path_len < kAccessLogLegacyTargetWidth && entry.path[path_len]) path_len++;
            for (i64 i = 0; i < path_len; i++) line[w++] = entry.path[i];
            break;
        }
        case AccessLogTargetState::Complete:
            if (entry.target_length == 0u || entry.target_length > kAccessLogCompleteTargetMax) {
                invalid_target();
                break;
            }
            for (i64 i = 0; i < static_cast<i64>(entry.target_length); i++)
                line[w++] = entry.path[i];
            break;
        case AccessLogTargetState::OverLimit:
            if (entry.target_length <= kAccessLogCompleteTargetMax ||
                entry.target_length > kAccessLogObservedStrictH1TargetMax) {
                invalid_target();
                break;
            }
            w += static_cast<i64>(copy_str(line + w, kOverLimitPrefix));
            w += static_cast<i64>(write_u64_dec(line + w, entry.target_length));
            line[w++] = '>';
            break;
        case AccessLogTargetState::Unavailable:
            if (entry.target_length != 0u)
                invalid_target();
            else
                w += static_cast<i64>(copy_str(line + w, kUnavailable));
            break;
        case AccessLogTargetState::Invalid:
        default:
            invalid_target();
            break;
    }
    line[w++] = ' ';

    w += static_cast<i64>(write_u64_dec(line + w, entry.status));
    line[w++] = ' ';
    w += static_cast<i64>(write_u64_dec(line + w, entry.duration_us));
    w += static_cast<i64>(copy_str(line + w, "us "));
    w += static_cast<i64>(write_u64_dec(line + w, entry.req_size));
    line[w++] = ' ';
    w += static_cast<i64>(write_u64_dec(line + w, entry.resp_size));
    line[w++] = ' ';
    w += static_cast<i64>(format_ipv4(line + w, entry.addr));

    // Upstream (if present)
    if (entry.upstream[0] != '\0') {
        line[w++] = ' ';
        i64 up_len = 0;
        while (up_len < sizeof(entry.upstream) && entry.upstream[up_len]) up_len++;
        for (i64 i = 0; i < up_len; i++) line[w++] = entry.upstream[i];
        line[w++] = ' ';
        w += static_cast<i64>(write_u64_dec(line + w, entry.upstream_us));
        w += static_cast<i64>(copy_str(line + w, "us"));
    }

    w += static_cast<i64>(copy_str(line + w, " s="));
    w += static_cast<i64>(write_u64_dec(line + w, entry.shard_id));
    if (entry.grpc_status_plus_one != 0 && entry.grpc_status_plus_one <= 17) {
        w += static_cast<i64>(copy_str(line + w, " grpc_status="));
        w += static_cast<i64>(write_u64_dec(
            line + w, static_cast<u64>(static_cast<i64>(entry.grpc_status_plus_one) - 1)));
    }
    line[w++] = '\n';
    if (w > static_cast<i64>(sizeof(line)) || buf == nullptr || static_cast<i64>(buf_size) < w)
        return 0;
    for (i64 i = 0; i < w; i++) buf[i] = line[i];
    return static_cast<u32>(w);
}

u32 format_access_log_downstream_request_bytes_line(const AccessLogEntry& entry,
                                                    char* buf,
                                                    u32 buf_size) {
    char line[kAccessLogDownstreamRequestBytesLineCapacity];
    i64 w = write_u64_dec(line, entry.req_size);
    line[w++] = '\n';
    if (buf == nullptr || static_cast<i64>(buf_size) < w) return 0;
    for (i64 i = 0; i < w; i++) buf[i] = line[i];
    return static_cast<u32>(w);
}

u32 format_access_log_downstream_host_line(const AccessLogEntry& entry,
                                           const AccessLogDownstreamHostRecord& host,
                                           char* buf,
                                           u32 buf_size) {
    if (buf == nullptr || host.record_schema != kAccessLogDownstreamHostRecordSchema ||
        host.reserved[0] != 0u || host.reserved[1] != 0u)
        return 0u;

    const char* state_name = nullptr;
    switch (host.state) {
        case AccessLogDownstreamHostState::Unavailable:
            if (host.observed_length != 0u) return 0u;
            state_name = "unavailable";
            break;
        case AccessLogDownstreamHostState::Complete:
            if (host.observed_length == 0u || host.observed_length > kAccessLogDownstreamHostMax)
                return 0u;
            state_name = "complete";
            break;
        case AccessLogDownstreamHostState::Empty:
            if (host.observed_length != 0u) return 0u;
            state_name = "empty";
            break;
        case AccessLogDownstreamHostState::Absent:
            if (host.observed_length != 0u) return 0u;
            state_name = "absent";
            break;
        case AccessLogDownstreamHostState::Duplicate:
            if (host.observed_length != 0u) return 0u;
            state_name = "duplicate";
            break;
        case AccessLogDownstreamHostState::OverLimit:
            if (host.observed_length <= kAccessLogDownstreamHostMax) return 0u;
            state_name = "over_limit";
            break;
        case AccessLogDownstreamHostState::Invalid:
            if (host.observed_length != 0u) return 0u;
            state_name = "invalid";
            break;
        default:
            return 0u;
    }
    if (host.state != AccessLogDownstreamHostState::Complete) {
        for (char byte : host.value)
            if (byte != '\0') return 0u;
    } else {
        for (i64 i = host.observed_length; i < static_cast<i64>(kAccessLogDownstreamHostMax); i++)
            if (host.value[i] != '\0') return 0u;
    }

    static constexpr char kHex[] = "0123456789abcdef";
    static_assert(static_cast<i64>(sizeof("host1 request_bytes=")) - 1 + 10 +
                      static_cast<i64>(sizeof(" status=")) - 1 + 5 +
                      static_cast<i64>(sizeof(" host_state=")) - 1 +
                      static_cast<i64>(sizeof("unavailable")) - 1 +
                      static_cast<i64>(sizeof(" host_length=")) - 1 + 10 +
                      static_cast<i64>(sizeof(" host_hex=")) - 1 +
                      2 * static_cast<i64>(kAccessLogDownstreamHostMax) +
                      static_cast<i64>(sizeof(" upstream_history=unavailable\n")) - 1 <=
                  static_cast<i64>(kAccessLogDownstreamHostLineCapacity));
    char line[kAccessLogDownstreamHostLineCapacity];
    i64 w = 0;
    w += static_cast<i64>(copy_str(line + w, "host1 request_bytes="));
    w += static_cast<i64>(write_u64_dec(line + w, entry.req_size));
    w += static_cast<i64>(copy_str(line + w, " status="));
    w += static_cast<i64>(write_u64_dec(line + w, entry.status));
    w += static_cast<i64>(copy_str(line + w, " host_state="));
    w += static_cast<i64>(copy_str(line + w, state_name));
    w += static_cast<i64>(copy_str(line + w, " host_length="));
    w += static_cast<i64>(write_u64_dec(line + w, host.observed_length));
    w += static_cast<i64>(copy_str(line + w, " host_hex="));
    if (host.state == AccessLogDownstreamHostState::Complete) {
        for (i64 i = 0; i < static_cast<i64>(host.observed_length); i++) {
            const u8 byte = static_cast<u8>(host.value[i]);
            line[w++] = kHex[byte >> 4u];
            line[w++] = kHex[byte & 0x0fu];
        }
    } else {
        line[w++] = '-';
    }
    w += static_cast<i64>(copy_str(line + w, " upstream_history=unavailable\n"));
    if (w > static_cast<i64>(sizeof(line)) || static_cast<i64>(buf_size) < w) return 0u;
    for (i64 i = 0; i < w; i++) buf[i] = line[i];
    return static_cast<u32>(w);
}

// --- write_with_poll ---

// Write all bytes to fd, using poll() to wait for writability.
// While *running_flag is true: retries indefinitely (no data loss).
// While *running_flag is false (shutdown): gives up after 5s stall.
// Write with non-blocking I/O + poll. Never blocks in write() — if the pipe/socket
// buffer is full, write returns EAGAIN and we re-poll. Small chunks (4KB) ensure
// write completes quickly even on pipes.
static bool write_with_poll(
    i32 fd, const u8* buf, u32 len, const std::atomic<bool>* running_flag, u32 max_stall = 50) {
    static constexpr u32 kChunkSize = 4096;  // bounded write size
    i64 written = 0;
    i64 stall_polls = 0;
    while (written < static_cast<i64>(len)) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        i32 rc = poll(&pfd, 1, 100);

        if (rc == 0) {
            if (!running_flag->load(std::memory_order_relaxed)) {
                if (++stall_polls >= static_cast<i64>(max_stall)) return false;
            }
            continue;
        }
        if (rc < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (pfd.revents & (POLLERR | POLLHUP)) {
            return false;
        }

        // Write in bounded chunks so we return to poll promptly.
        i64 to_write = static_cast<i64>(len) - written;
        if (to_write > static_cast<i64>(kChunkSize)) to_write = kChunkSize;
        ssize_t n = ::write(fd, buf + written, to_write);
        if (n > 0) {
            written += static_cast<i64>(n);
            stall_polls = 0;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            continue;  // transient — re-poll
        } else {
            return false;
        }
    }
    return true;
}

// --- AccessLogFlusher ---

void AccessLogRing::init(bool capture_path_only) {
    path_only = capture_path_only;
    write_pos = 0;
    read_pos = 0;
}

bool AccessLogRing::push(const AccessLogEntry& entry) {
    u32 wp = write_pos.load(std::memory_order_relaxed);
    u32 rp = read_pos.load(std::memory_order_acquire);

    const i64 distance =
        static_cast<i64>(static_cast<u32>(static_cast<i64>(wp) - static_cast<i64>(rp)));
    if (distance >= static_cast<i64>(kCapacity)) {
        return false;  // full — drop this entry
    }

    entries[wp & kMask] = entry;
    write_pos.store(static_cast<u32>(static_cast<i64>(wp) + 1), std::memory_order_release);
    return true;
}

bool AccessLogRing::pop(AccessLogEntry& out) {
    u32 rp = read_pos.load(std::memory_order_relaxed);
    u32 wp = write_pos.load(std::memory_order_acquire);

    if (rp == wp) return false;  // empty

    out = entries[rp & kMask];
    read_pos.store(static_cast<u32>(static_cast<i64>(rp) + 1), std::memory_order_release);
    return true;
}

u32 AccessLogRing::available() const {
    u32 wp = write_pos.load(std::memory_order_acquire);
    u32 rp = read_pos.load(std::memory_order_relaxed);
    return static_cast<u32>(static_cast<i64>(wp) - static_cast<i64>(rp));
}

// Local receivers expect the traditional libc syslog envelope. Network
// listeners default to RFC 5424 and can opt in to the BSD envelope.
static bool resolve_syslog_address(const char* endpoint, AccessLogSyslogDestination& out) {
    if (strncmp(endpoint, "unix:", 5) == 0) {
        const char* path = endpoint + 5;
        sockaddr_un local{};
        const size_t length = strnlen(path, sizeof(local.sun_path));
        if (path[0] != '/' || length == sizeof(local.sun_path)) return false;
        local.sun_family = AF_UNIX;
        i64 path_length = 0;
        if (!try_u64_to_i64(static_cast<u64>(length), path_length)) return false;
        const i64 address_length =
            static_cast<i64>(offsetof(sockaddr_un, sun_path)) + path_length + 1;
        out.address_length = static_cast<socklen_t>(address_length);
#ifdef __APPLE__
        local.sun_len = static_cast<decltype(local.sun_len)>(out.address_length);
#endif
        memcpy(local.sun_path, path, static_cast<size_t>(path_length + 1));
        memcpy(&out.address, &local, sizeof(local));
        return true;
    }

    if (strncmp(endpoint, "udp://", 6) != 0) return false;
    const char* host = endpoint + 6;
    const char* end = nullptr;
    const char* port = "514";
    if (*host == '[') {
        ++host;
        end = strchr(host, ']');
        if (!end || (end[1] != '\0' && end[1] != ':')) return false;
        if (end[1] == ':') port = end + 2;
    } else {
        end = strchr(host, ':');
        if (end)
            port = end + 1;
        else
            end = strchr(host, '\0');
    }
    const auto host_length = end - host;
    char name[256];
    if (host_length <= 0 || host_length >= static_cast<i64>(sizeof(name))) return false;
    i32 number = 0;
    for (const char* digit = port; *digit != '\0'; ++digit) {
        if (*digit < '0' || *digit > '9') return false;
        number = number * 10 + (*digit - '0');
        if (number > 65535) return false;
    }
    if (number == 0) return false;
    memcpy(name, host, static_cast<size_t>(host_length));
    name[host_length] = '\0';
    addrinfo hints{};
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_NUMERICSERV;
    addrinfo* addresses = nullptr;
    if (getaddrinfo(name, port, &hints, &addresses) != 0) return false;
    for (const addrinfo* address = addresses; address; address = address->ai_next) {
        if ((address->ai_family == AF_INET || address->ai_family == AF_INET6) &&
            address->ai_addrlen <= sizeof(out.address)) {
            memcpy(&out.address, address->ai_addr, address->ai_addrlen);
            out.address_length = address->ai_addrlen;
            break;
        }
    }
    freeaddrinfo(addresses);
    return out.address_length != 0;
}

core::Expected<i32, Error> open_access_log_syslog(const char* endpoint,
                                                  AccessLogSyslogFormat format,
                                                  AccessLogSyslogDestination& destination) {
    AccessLogSyslogDestination resolved{};
    if (!endpoint || !resolve_syslog_address(endpoint, resolved))
        return core::make_unexpected(Error::make(EINVAL, Error::Source::Socket));

    if (format == AccessLogSyslogFormat::Auto)
        format = resolved.address.ss_family == AF_UNIX ? AccessLogSyslogFormat::Rfc3164
                                                       : AccessLogSyslogFormat::Rfc5424;
    resolved.format = format;
    if (gethostname(resolved.hostname, sizeof(resolved.hostname) - 1) != 0 ||
        resolved.hostname[0] == '\0')
        strcpy(resolved.hostname, "-");
    for (char* byte = resolved.hostname; *byte != '\0'; ++byte)
        if (*byte <= ' ' || *byte > '~') *byte = '_';
    resolved.process_id = static_cast<i32>(getpid());

    const i32 fd = socket(resolved.address.ss_family, SOCK_DGRAM, 0);
    if (fd < 0) return core::make_unexpected(Error::from_errno(Error::Source::Socket));
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
        const auto error = Error::from_errno(Error::Source::Socket);
        close(fd);
        return core::make_unexpected(error);
    }
    destination = resolved;
    return fd;
}

void AccessLogFlusher::record_syslog_failure() {
    static constexpr i64 kMaxSyslogSendFailures = static_cast<i64>(~u64{0} >> 1);
    if (syslog_send_failures_ < kMaxSyslogSendFailures) ++syslog_send_failures_;
}

void AccessLogFlusher::send_syslog(const AccessLogEntry& entry, const char* line, u32 length) {
    char header[128];
    i32 header_length = 0;
    // Facility local0, severity informational.
    if (syslog_.format == AccessLogSyslogFormat::Rfc5424) {
        header_length = snprintf(header,
                                 sizeof(header),
                                 "<134>1 %.24s %s rut-access %d - - ",
                                 line,
                                 syslog_.hostname,
                                 syslog_.process_id);
    } else {
        time_t seconds = 0;
        if (__builtin_add_overflow(entry.timestamp_us / 1000000, u64{0}, &seconds)) {
            record_syslog_failure();
            return;
        }
        tm local{};
        if (!localtime_r(&seconds, &local) || local.tm_mon < 0 || local.tm_mon >= 12) {
            record_syslog_failure();
            return;
        }
        static constexpr const char* months[] = {
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
        const char* host = syslog_.address.ss_family == AF_UNIX ? "" : syslog_.hostname;
        header_length = snprintf(header,
                                 sizeof(header),
                                 "<134>%s %2d %02d:%02d:%02d %s%s"
                                 "rut-access[%d]: ",
                                 months[local.tm_mon],
                                 local.tm_mday,
                                 local.tm_hour,
                                 local.tm_min,
                                 local.tm_sec,
                                 host,
                                 *host ? " " : "",
                                 syslog_.process_id);
    }
    if (header_length <= 0 || header_length >= static_cast<i32>(sizeof(header))) {
        record_syslog_failure();
        return;
    }
    static constexpr i64 kMessageCapacity =
        static_cast<i64>(sizeof(header)) + static_cast<i64>(kAccessLogTextLineCapacity);
    char message[kMessageCapacity];
    memcpy(message, header, static_cast<size_t>(header_length));
    const i64 payload_length = static_cast<i64>(length) - 1;  // strip file record delimiter
    for (i64 i = 0; i < payload_length; ++i) {
        const auto byte = static_cast<unsigned char>(line[i]);
        message[static_cast<i64>(header_length) + i] = byte < 32 || byte == 127 ? '?' : line[i];
    }
    const i64 size = header_length + payload_length;
    ssize_t sent;
    do {
        sent = sendto(output_fd,
                      message,
                      static_cast<size_t>(size),
                      0,
                      reinterpret_cast<const sockaddr*>(&syslog_.address),
                      syslog_.address_length);
    } while (sent < 0 && errno == EINTR);
    if (sent != size) record_syslog_failure();
}

void AccessLogFlusher::init(i32 fd, bool compress_enabled, i32 level, u32 interval_ms) {
    ring_count = 0;
    syslog_ = {};
    syslog_send_failures_ = 0;
    output_fd = fd;
    flush_interval_ms = interval_ms;
    compress = compress_enabled;
    // Clamp level to supported range (fast + doubleFast only).
    if (level < kMinLevel) level = kMinLevel;
    if (level > kMaxLevel) level = kMaxLevel;
    compress_level = level;
    thread = 0;
    running = false;
    zstd_ctx = nullptr;
    for (u32 i = 0; i < kMaxRings; i++) rings[i] = nullptr;
}

void AccessLogFlusher::init_syslog(i32 fd, const AccessLogSyslogDestination& destination) {
    init(fd);
    syslog_ = destination;
}

void AccessLogFlusher::add_ring(AccessLogRing* ring) {
    if (ring_count < kMaxRings) {
        rings[ring_count++] = ring;
    }
}

core::Expected<void, Error> AccessLogFlusher::start() {
    if (running.load(std::memory_order_relaxed)) return {};

    // Set output fd non-blocking so write() never blocks the flusher thread.
    // Combined with poll(POLLOUT) + bounded 4KB chunks, this guarantees the
    // flusher can always check the running flag between writes.
    i32 flags = fcntl(output_fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(output_fd, F_SETFL, flags | O_NONBLOCK);
    }

    // Initialize zstd streaming context if compression enabled.
    if (compress) {
        auto* cstream = ZSTD_createCStream();
        if (!cstream) {
            return core::make_unexpected(Error::make(ENOMEM, Error::Source::Mmap));
        }
        size_t zrc = ZSTD_initCStream(cstream, compress_level);
        if (ZSTD_isError(zrc)) {
            ZSTD_freeCStream(cstream);
            return core::make_unexpected(Error::make(EINVAL, Error::Source::Mmap));
        }
        zstd_ctx = cstream;
    }

    running.store(true, std::memory_order_relaxed);
    i32 rc = pthread_create(&thread, nullptr, thread_entry, this);
    if (rc != 0) {
        running.store(false, std::memory_order_relaxed);
        if (zstd_ctx) {
            ZSTD_freeCStream(static_cast<ZSTD_CStream*>(zstd_ctx));
            zstd_ctx = nullptr;
        }
        return core::make_unexpected(Error::make(rc, Error::Source::Thread));
    }
    return {};
}

void AccessLogFlusher::stop() {
    if (!running.load(std::memory_order_relaxed)) return;
    running.store(false, std::memory_order_release);
    pthread_join(thread, nullptr);

    // Flush remaining zstd data and free context.
    if (zstd_ctx) {
        auto* cstream = static_cast<ZSTD_CStream*>(zstd_ctx);
        // End the zstd frame to produce a valid .zst file.
        // ZSTD_endStream must be called repeatedly until it returns 0,
        // indicating all compressed data (including the end marker) has
        // been flushed to the output buffer.
        //
        // running is already false (set above to stop the flusher thread).
        // Use a longer stall limit (300 × 100ms = 30s) so the zstd
        // end-frame survives transient backpressure, but stop() still
        // returns if the sink is permanently wedged.
        static constexpr u32 kFinishMaxStall = 300;  // 30 seconds
        static constexpr u32 kOutBufSize = 4096;
        u8 out_buf[kOutBufSize];
        for (;;) {
            ZSTD_outBuffer output = {out_buf, sizeof(out_buf), 0};
            size_t remaining = ZSTD_endStream(cstream, &output);
            if (output.pos > 0) {
                write_with_poll(
                    output_fd, out_buf, static_cast<u32>(output.pos), &running, kFinishMaxStall);
            }
            if (ZSTD_isError(remaining) || remaining == 0) break;
        }
        ZSTD_freeCStream(cstream);
        zstd_ctx = nullptr;
    }
}

bool AccessLogFlusher::flush_batch(const u8* data, u32 len) {
    if (!compress || !zstd_ctx) {
        // Plain text: write directly.
        return write_with_poll(output_fd, data, len, &running);
    }

    // Compress with zstd streaming and write compressed output.
    auto* cstream = static_cast<ZSTD_CStream*>(zstd_ctx);
    ZSTD_inBuffer input = {data, len, 0};
    static constexpr u32 kOutBufSize = 65536 + 512;  // >= ZSTD_CStreamOutSize()
    u8 out_buf[kOutBufSize];

    while (input.pos < input.size) {
        ZSTD_outBuffer output = {out_buf, sizeof(out_buf), 0};
        size_t rc = ZSTD_compressStream(cstream, &output, &input);
        if (ZSTD_isError(rc)) return false;
        if (output.pos > 0) {
            if (!write_with_poll(output_fd, out_buf, static_cast<u32>(output.pos), &running)) {
                return false;
            }
        }
    }

    // Flush until zstd reports that no buffered data remains.
    for (;;) {
        ZSTD_outBuffer output = {out_buf, sizeof(out_buf), 0};
        size_t remaining = ZSTD_flushStream(cstream, &output);
        if (ZSTD_isError(remaining)) return false;
        if (output.pos > 0) {
            if (!write_with_poll(output_fd, out_buf, static_cast<u32>(output.pos), &running)) {
                return false;
            }
        }
        if (remaining == 0) break;
    }
    return true;
}

u32 AccessLogFlusher::flush_once() {
    // Batch buffer: accumulate text lines, then write (or compress+write).
    static constexpr u32 kBatchSize = 65536;  // 64KB text batch
    char batch[kBatchSize];
    i64 batch_len = 0;
    i64 total = 0;
    AccessLogEntry entry;
    char line[kAccessLogTextLineCapacity];

    for (u32 i = 0; i < ring_count; i++) {
        while (rings[i]->pop(entry)) {
            u32 n = format_access_log_text(entry, line, sizeof(line));
            if (n > 0 && syslog_.address_length != 0) {
                send_syslog(entry, line, n);
            } else if (n > 0) {
                // Flush batch if this line won't fit.
                if (batch_len + static_cast<i64>(n) > static_cast<i64>(kBatchSize)) {
                    if (!flush_batch(reinterpret_cast<const u8*>(batch),
                                     static_cast<u32>(batch_len))) {
                        return static_cast<u32>(total);
                    }
                    batch_len = 0;
                }
                for (i64 j = 0; j < static_cast<i64>(n); j++) batch[batch_len + j] = line[j];
                batch_len += static_cast<i64>(n);
            }
            total++;
        }
    }

    // Flush remaining.
    if (batch_len > 0) {
        if (!flush_batch(reinterpret_cast<const u8*>(batch), static_cast<u32>(batch_len))) {
            return static_cast<u32>(total);
        }
    }
    return static_cast<u32>(total);
}

void* AccessLogFlusher::thread_entry(void* arg) {
    auto* self = static_cast<AccessLogFlusher*>(arg);

    struct timespec sleep_ts;
    sleep_ts.tv_sec = self->flush_interval_ms / 1000;
    sleep_ts.tv_nsec = static_cast<long>(self->flush_interval_ms % 1000) * 1000000L;

    while (self->running.load(std::memory_order_acquire)) {
        self->flush_once();
        nanosleep(&sleep_ts, nullptr);
    }

    // Final flush — drain all remaining entries.
    self->flush_once();
    return nullptr;
}

}  // namespace rut
