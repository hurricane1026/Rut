#include "rut/runtime/access_log.h"

#include <atomic>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <zstd.h>

namespace rut {

// --- Text formatting helpers (no stdlib) ---

static thread_local u64 g_last_monotonic_us = 1;

u64 realtime_us() {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0;
    return static_cast<u64>(ts.tv_sec) * 1000000ULL + static_cast<u64>(ts.tv_nsec) / 1000ULL;
}

u64 monotonic_us() {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return g_last_monotonic_us;
    u64 now = static_cast<u64>(ts.tv_sec) * 1000000ULL + static_cast<u64>(ts.tv_nsec) / 1000ULL;
    if (now == 0) now = 1;
    g_last_monotonic_us = now;
    return now;
}

static u32 write_u64_dec(char* buf, u64 val) {
    if (val == 0) {
        buf[0] = '0';
        return 1;
    }
    char tmp[20];
    u32 n = 0;
    while (val > 0) {
        tmp[n++] = static_cast<char>('0' + val % 10);
        val /= 10;
    }
    for (u32 i = 0; i < n; i++) buf[i] = tmp[n - 1 - i];
    return n;
}

static u32 copy_str(char* dst, const char* src) {
    u32 n = 0;
    while (src[n]) {
        dst[n] = src[n];
        n++;
    }
    return n;
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

    u32 w = 0;
    u32 year = static_cast<u32>(tm.tm_year + 1900);
    buf[w++] = static_cast<char>('0' + year / 1000);
    buf[w++] = static_cast<char>('0' + (year / 100) % 10);
    buf[w++] = static_cast<char>('0' + (year / 10) % 10);
    buf[w++] = static_cast<char>('0' + year % 10);
    buf[w++] = '-';
    u32 mon = static_cast<u32>(tm.tm_mon + 1);
    buf[w++] = static_cast<char>('0' + mon / 10);
    buf[w++] = static_cast<char>('0' + mon % 10);
    buf[w++] = '-';
    u32 day = static_cast<u32>(tm.tm_mday);
    buf[w++] = static_cast<char>('0' + day / 10);
    buf[w++] = static_cast<char>('0' + day % 10);
    buf[w++] = 'T';
    u32 hour = static_cast<u32>(tm.tm_hour);
    buf[w++] = static_cast<char>('0' + hour / 10);
    buf[w++] = static_cast<char>('0' + hour % 10);
    buf[w++] = ':';
    u32 min = static_cast<u32>(tm.tm_min);
    buf[w++] = static_cast<char>('0' + min / 10);
    buf[w++] = static_cast<char>('0' + min % 10);
    buf[w++] = ':';
    u32 sec = static_cast<u32>(tm.tm_sec);
    buf[w++] = static_cast<char>('0' + sec / 10);
    buf[w++] = static_cast<char>('0' + sec % 10);
    buf[w++] = '.';
    buf[w++] = static_cast<char>('0' + millis / 100);
    buf[w++] = static_cast<char>('0' + (millis / 10) % 10);
    buf[w++] = static_cast<char>('0' + millis % 10);
    buf[w++] = 'Z';
    return w;
}

// Format IPv4 from network byte order.
// Format IPv4 from network byte order.
// Access raw bytes to be endian-safe (works on both LE and BE hosts).
static u32 format_ipv4(char* buf, u32 addr) {
    const auto* bytes = reinterpret_cast<const u8*>(&addr);
    u32 w = 0;
    for (u32 i = 0; i < 4; i++) {
        if (i > 0) buf[w++] = '.';
        u8 octet = bytes[i];
        if (octet >= 100) buf[w++] = static_cast<char>('0' + octet / 100);
        if (octet >= 10) buf[w++] = static_cast<char>('0' + (octet / 10) % 10);
        buf[w++] = static_cast<char>('0' + octet % 10);
    }
    return w;
}

// Format: "2026-03-23T15:30:00.123Z GET /path 200 1234us 256 1024 10.0.0.5 s=3\n"
// Compact, greppable, no quoting needed for simple paths.
u32 format_access_log_text(const AccessLogEntry& entry, char* buf, u32 buf_size) {
    if (buf_size < 256) return 0;
    u32 w = 0;

    w += format_timestamp(buf + w, entry.timestamp_us);
    buf[w++] = ' ';
    w += copy_str(buf + w, method_str(entry.method));
    buf[w++] = ' ';

    // Path (null-terminated, no escaping — truncate if needed)
    u32 path_len = 0;
    while (path_len < sizeof(entry.path) && entry.path[path_len]) path_len++;
    for (u32 i = 0; i < path_len && w + 80 < buf_size; i++) buf[w++] = entry.path[i];
    buf[w++] = ' ';

    w += write_u64_dec(buf + w, entry.status);
    buf[w++] = ' ';
    w += write_u64_dec(buf + w, entry.duration_us);
    w += copy_str(buf + w, "us ");
    w += write_u64_dec(buf + w, entry.req_size);
    buf[w++] = ' ';
    w += write_u64_dec(buf + w, entry.resp_size);
    buf[w++] = ' ';
    w += format_ipv4(buf + w, entry.addr);

    // Upstream (if present)
    if (entry.upstream[0] != '\0') {
        buf[w++] = ' ';
        u32 up_len = 0;
        while (up_len < sizeof(entry.upstream) && entry.upstream[up_len]) up_len++;
        for (u32 i = 0; i < up_len; i++) buf[w++] = entry.upstream[i];
        buf[w++] = ' ';
        w += write_u64_dec(buf + w, entry.upstream_us);
        w += copy_str(buf + w, "us");
    }

    w += copy_str(buf + w, " s=");
    w += write_u64_dec(buf + w, entry.shard_id);
    buf[w++] = '\n';
    return w;
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
    u32 written = 0;
    u32 stall_polls = 0;
    while (written < len) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        i32 rc = poll(&pfd, 1, 100);

        if (rc == 0) {
            if (!running_flag->load(std::memory_order_relaxed)) {
                if (++stall_polls >= max_stall) return false;
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
        u32 to_write = len - written;
        if (to_write > kChunkSize) to_write = kChunkSize;
        ssize_t n = ::write(fd, buf + written, to_write);
        if (n > 0) {
            written += static_cast<u32>(n);
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

void AccessLogRing::init() {
    write_pos = 0;
    read_pos = 0;
}

bool AccessLogRing::push(const AccessLogEntry& entry) {
    u32 wp = write_pos.load(std::memory_order_relaxed);
    u32 rp = read_pos.load(std::memory_order_acquire);

    if (wp - rp >= kCapacity) {
        return false;  // full — drop this entry
    }

    entries[wp & kMask] = entry;
    write_pos.store(wp + 1, std::memory_order_release);
    return true;
}

bool AccessLogRing::pop(AccessLogEntry& out) {
    u32 rp = read_pos.load(std::memory_order_relaxed);
    u32 wp = write_pos.load(std::memory_order_acquire);

    if (rp == wp) return false;  // empty

    out = entries[rp & kMask];
    read_pos.store(rp + 1, std::memory_order_release);
    return true;
}

u32 AccessLogRing::available() const {
    u32 wp = write_pos.load(std::memory_order_acquire);
    u32 rp = read_pos.load(std::memory_order_relaxed);
    return wp - rp;
}

void AccessLogFlusher::init(i32 fd, bool compress_enabled, i32 level, u32 interval_ms) {
    ring_count = 0;
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
    u32 batch_len = 0;
    u32 total = 0;
    AccessLogEntry entry;
    char line[512];

    for (u32 i = 0; i < ring_count; i++) {
        while (rings[i]->pop(entry)) {
            u32 n = format_access_log_text(entry, line, sizeof(line));
            if (n > 0) {
                // Flush batch if this line won't fit.
                if (batch_len + n > kBatchSize) {
                    if (!flush_batch(reinterpret_cast<const u8*>(batch), batch_len)) {
                        return total;
                    }
                    batch_len = 0;
                }
                for (u32 j = 0; j < n; j++) batch[batch_len + j] = line[j];
                batch_len += n;
            }
            total++;
        }
    }

    // Flush remaining.
    if (batch_len > 0) {
        if (!flush_batch(reinterpret_cast<const u8*>(batch), batch_len)) {
            return total;
        }
    }
    return total;
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
