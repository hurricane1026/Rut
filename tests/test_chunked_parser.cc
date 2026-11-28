#include "rut/runtime/chunked_parser.h"
#include "test.h"

using namespace rut;

// ============================================================================
// Helpers
// ============================================================================

// Feed all of `input` through the parser, collecting decoded body into `body`.
// Returns the final ChunkStatus (Done or Error).
static ChunkStatus feed_all(
    ChunkedParser* p, const u8* input, u32 in_len, u8* body, u32* body_len) {
    *body_len = 0;
    u32 offset = 0;

    while (offset < in_len) {
        u32 consumed = 0;
        u32 out_start = 0;
        u32 out_len = 0;

        ChunkStatus s = p->feed(input + offset, in_len - offset, &consumed, &out_start, &out_len);

        if (s == ChunkStatus::Data) {
            for (u32 i = 0; i < out_len; i++) {
                body[*body_len + i] = input[offset + out_start + i];
            }
            *body_len += out_len;
            offset += consumed;
        } else if (s == ChunkStatus::NeedMore) {
            offset += consumed;
            break;
        } else {
            // Done or Error
            offset += consumed;
            return s;
        }
    }
    return ChunkStatus::NeedMore;
}

static bool mem_eq(const u8* a, const char* b, u32 len) {
    for (u32 i = 0; i < len; i++) {
        if (a[i] != static_cast<u8>(b[i])) return false;
    }
    return true;
}

static u32 str_len(const char* s) {
    u32 n = 0;
    while (s[n]) n++;
    return n;
}

// ============================================================================
// Tests
// ============================================================================

TEST(chunked, single) {
    ChunkedParser p;
    p.reset();

    const char* raw = "5\r\nhello\r\n0\r\n\r\n";
    auto len = str_len(raw);
    u8 body[256];
    u32 body_len = 0;

    ChunkStatus s = feed_all(&p, reinterpret_cast<const u8*>(raw), len, body, &body_len);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ChunkStatus::Done));
    CHECK_EQ(body_len, 5u);
    CHECK(mem_eq(body, "hello", 5));
}

TEST(chunked, multiple) {
    ChunkedParser p;
    p.reset();

    const char* raw = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    auto len = str_len(raw);
    u8 body[256];
    u32 body_len = 0;

    ChunkStatus s = feed_all(&p, reinterpret_cast<const u8*>(raw), len, body, &body_len);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ChunkStatus::Done));
    CHECK_EQ(body_len, 11u);
    CHECK(mem_eq(body, "hello world", 11));
}

TEST(chunked, accepts_large_chunk_size_incrementally) {
    ChunkedParser p;
    p.reset();
    const u8 header[] = "100000000\r\n";  // 4 GiB, without allocating the body.
    u32 consumed = 0, out_start = 0, out_len = 0;
    CHECK_EQ(p.feed(header, sizeof(header) - 1, &consumed, &out_start, &out_len),
             ChunkStatus::NeedMore);
    CHECK_EQ(consumed, sizeof(header) - 1);
    CHECK_EQ(p.chunk_remaining, i64{0x1'0000'0000});

    const u8 byte = 'x';
    CHECK_EQ(p.feed(&byte, 1, &consumed, &out_start, &out_len), ChunkStatus::Data);
    CHECK_EQ(out_len, 1u);
    CHECK_EQ(p.chunk_remaining, i64{0xFFFF'FFFF});
}

TEST(chunked, rejects_chunk_size_over_i64) {
    ChunkedParser p;
    p.reset();
    const u8 input[] = "8000000000000000\r\n";
    u32 consumed = 0, out_start = 0, out_len = 0;
    CHECK_EQ(p.feed(input, sizeof(input) - 1, &consumed, &out_start, &out_len), ChunkStatus::Error);
}

TEST(chunked, hex_upper) {
    ChunkedParser p;
    p.reset();

    const char* raw = "A\r\n0123456789\r\n0\r\n\r\n";
    auto len = str_len(raw);
    u8 body[256];
    u32 body_len = 0;

    ChunkStatus s = feed_all(&p, reinterpret_cast<const u8*>(raw), len, body, &body_len);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ChunkStatus::Done));
    CHECK_EQ(body_len, 10u);
    CHECK(mem_eq(body, "0123456789", 10));
}

TEST(chunked, hex_lower) {
    ChunkedParser p;
    p.reset();

    const char* raw = "a\r\n0123456789\r\n0\r\n\r\n";
    auto len = str_len(raw);
    u8 body[256];
    u32 body_len = 0;

    ChunkStatus s = feed_all(&p, reinterpret_cast<const u8*>(raw), len, body, &body_len);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ChunkStatus::Done));
    CHECK_EQ(body_len, 10u);
    CHECK(mem_eq(body, "0123456789", 10));
}

TEST(chunked, extension) {
    ChunkedParser p;
    p.reset();

    const char* raw = "5;ext=val\r\nhello\r\n0\r\n\r\n";
    auto len = str_len(raw);
    u8 body[256];
    u32 body_len = 0;

    ChunkStatus s = feed_all(&p, reinterpret_cast<const u8*>(raw), len, body, &body_len);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ChunkStatus::Done));
    CHECK_EQ(body_len, 5u);
    CHECK(mem_eq(body, "hello", 5));
}

TEST(chunked, trailer) {
    ChunkedParser p;
    p.reset();

    const char* raw = "0\r\nTrailer: value\r\n\r\n";
    auto len = str_len(raw);
    u8 body[256];
    u32 body_len = 0;

    ChunkStatus s = feed_all(&p, reinterpret_cast<const u8*>(raw), len, body, &body_len);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ChunkStatus::Done));
    CHECK_EQ(body_len, 0u);
}

TEST(chunked, empty) {
    ChunkedParser p;
    p.reset();

    const char* raw = "0\r\n\r\n";
    auto len = str_len(raw);
    u8 body[256];
    u32 body_len = 0;

    ChunkStatus s = feed_all(&p, reinterpret_cast<const u8*>(raw), len, body, &body_len);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ChunkStatus::Done));
    CHECK_EQ(body_len, 0u);
}

TEST(chunked, incremental) {
    // Feed bytes one at a time.
    ChunkedParser p;
    p.reset();

    const char* raw = "5\r\nhello\r\n0\r\n\r\n";
    auto len = str_len(raw);
    const auto* input = reinterpret_cast<const u8*>(raw);

    u8 body[256];
    u32 body_len = 0;
    u32 offset = 0;
    ChunkStatus final_status = ChunkStatus::NeedMore;

    while (offset < len) {
        u32 consumed = 0;
        u32 out_start = 0;
        u32 out_len = 0;

        ChunkStatus s = p.feed(input + offset, 1, &consumed, &out_start, &out_len);

        if (s == ChunkStatus::Data) {
            for (u32 i = 0; i < out_len; i++) {
                body[body_len + i] = input[offset + out_start + i];
            }
            body_len += out_len;
            offset += consumed;
        } else if (s == ChunkStatus::NeedMore) {
            offset += consumed;
            // If consumed == 0 and we fed 1 byte, still advance.
            if (consumed == 0) offset++;
        } else {
            offset += consumed;
            final_status = s;
            break;
        }
    }

    CHECK_EQ(static_cast<u8>(final_status), static_cast<u8>(ChunkStatus::Done));
    CHECK_EQ(body_len, 5u);
    CHECK(mem_eq(body, "hello", 5));
}

TEST(chunked, large) {
    ChunkedParser p;
    p.reset();

    // Build: "3e8\r\n" + 1000 bytes + "\r\n0\r\n\r\n"
    static u8 buf[2048];
    u32 pos = 0;

    // "3e8\r\n" (0x3e8 = 1000)
    buf[pos++] = '3';
    buf[pos++] = 'e';
    buf[pos++] = '8';
    buf[pos++] = '\r';
    buf[pos++] = '\n';

    // 1000 bytes of data
    for (u32 i = 0; i < 1000; i++) {
        buf[pos++] = static_cast<u8>('A' + (i % 26));
    }

    // "\r\n0\r\n\r\n"
    buf[pos++] = '\r';
    buf[pos++] = '\n';
    buf[pos++] = '0';
    buf[pos++] = '\r';
    buf[pos++] = '\n';
    buf[pos++] = '\r';
    buf[pos++] = '\n';

    u8 body[1024];
    u32 body_len = 0;

    ChunkStatus s = feed_all(&p, buf, pos, body, &body_len);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ChunkStatus::Done));
    CHECK_EQ(body_len, 1000u);

    // Verify first few bytes
    CHECK_EQ(body[0], static_cast<u8>('A'));
    CHECK_EQ(body[1], static_cast<u8>('B'));
    CHECK_EQ(body[25], static_cast<u8>('Z'));
    CHECK_EQ(body[26], static_cast<u8>('A'));
}

TEST(chunked, split_across_calls) {
    const char* raw = "5\r\nhello\r\n0\r\n\r\n";
    auto len = str_len(raw);
    const auto* input = reinterpret_cast<const u8*>(raw);

    // Split at every possible byte boundary and verify correctness.
    for (u32 split = 1; split < len; split++) {
        ChunkedParser p;
        p.reset();

        u8 body[256];
        u32 body_len = 0;
        ChunkStatus final_status = ChunkStatus::NeedMore;

        // Feed first part.
        u32 offset = 0;
        while (offset < split) {
            u32 consumed = 0;
            u32 out_start = 0;
            u32 out_len = 0;
            u32 remaining = split - offset;

            ChunkStatus s = p.feed(input + offset, remaining, &consumed, &out_start, &out_len);

            if (s == ChunkStatus::Data) {
                for (u32 i = 0; i < out_len; i++) {
                    body[body_len + i] = input[offset + out_start + i];
                }
                body_len += out_len;
            } else if (s == ChunkStatus::Done || s == ChunkStatus::Error) {
                final_status = s;
                break;
            }
            offset += consumed;
            if (consumed == 0) break;
        }

        if (final_status != ChunkStatus::NeedMore) {
            // Might have completed in the first part; verify.
            if (final_status == ChunkStatus::Done) {
                CHECK_EQ(body_len, 5u);
                CHECK(mem_eq(body, "hello", 5));
            }
            continue;
        }

        // Feed second part.
        offset = split;
        while (offset < len) {
            u32 consumed = 0;
            u32 out_start = 0;
            u32 out_len = 0;
            u32 remaining = len - offset;

            ChunkStatus s = p.feed(input + offset, remaining, &consumed, &out_start, &out_len);

            if (s == ChunkStatus::Data) {
                for (u32 i = 0; i < out_len; i++) {
                    body[body_len + i] = input[offset + out_start + i];
                }
                body_len += out_len;
            } else if (s == ChunkStatus::Done || s == ChunkStatus::Error) {
                final_status = s;
                offset += consumed;
                break;
            }
            offset += consumed;
            if (consumed == 0) break;
        }

        CHECK_EQ(static_cast<u8>(final_status), static_cast<u8>(ChunkStatus::Done));
        CHECK_EQ(body_len, 5u);
        CHECK(mem_eq(body, "hello", 5));
    }
}

TEST(chunked, invalid_hex) {
    ChunkedParser p;
    p.reset();

    const char* raw = "XY\r\n";
    auto len = str_len(raw);
    u8 body[256];
    u32 body_len = 0;

    ChunkStatus s = feed_all(&p, reinterpret_cast<const u8*>(raw), len, body, &body_len);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ChunkStatus::Error));
}

TEST(chunked, missing_crlf) {
    ChunkedParser p;
    p.reset();

    const char* raw = "5\r\nhelloX";
    auto len = str_len(raw);
    u8 body[256];
    u32 body_len = 0;

    ChunkStatus s = feed_all(&p, reinterpret_cast<const u8*>(raw), len, body, &body_len);

    // After consuming "hello", parser expects \r but gets X.
    // feed_all returns Data for "hello" first, then on next call gets Error.
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ChunkStatus::Error));
}

TEST(chunked, accepts_wide_chunk_size) {
    ChunkedParser p;
    p.reset();

    const char* raw = "FFFFFFFF1\r\n";
    auto len = str_len(raw);
    u32 consumed = 0, out_start = 0, out_len = 0;
    CHECK_EQ(p.feed(reinterpret_cast<const u8*>(raw), len, &consumed, &out_start, &out_len),
             ChunkStatus::NeedMore);
    CHECK_EQ(p.chunk_remaining, i64{0xFFFF'FFFF1});
}

// ============================================================================
// Main
// Empty size (no hex digits before \r or ;)
TEST(chunk, empty_size_cr) {
    // "\r\n\r\n" — no hex digits before \r → Error
    const u8 input[] = "\r\n\r\n";
    ChunkedParser p;
    p.reset();
    u32 consumed = 0, out_start = 0, out_len = 0;
    CHECK_EQ(static_cast<u8>(p.feed(input, 4, &consumed, &out_start, &out_len)),
             static_cast<u8>(ChunkStatus::Error));
}

TEST(chunk, empty_size_semicolon) {
    // ";ext\r\n\r\n" — no hex digits before ; → Error
    const u8 input[] = ";ext\r\n\r\n";
    ChunkedParser p;
    p.reset();
    u32 consumed = 0, out_start = 0, out_len = 0;
    CHECK_EQ(static_cast<u8>(p.feed(input, 8, &consumed, &out_start, &out_len)),
             static_cast<u8>(ChunkStatus::Error));
}

// === Error edge cases for coverage ===

TEST(error, size_lf_missing) {
    // "3\rX" — \r in size line followed by non-\n → Error in SizeLF
    const u8 input[] = "3\rX";
    ChunkedParser p;
    p.reset();
    u32 consumed = 0, out_start = 0, out_len = 0;
    // First feed: "3" → Size, "\r" → SizeLF state
    // "X" → not \n → Error
    ChunkStatus s = p.feed(input, 3, &consumed, &out_start, &out_len);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ChunkStatus::Error));
}

TEST(error, data_lf_missing) {
    // After reading chunk data, \r must be followed by \n
    // "3\r\nabc\rX" — data "abc" complete, DataCR→DataLF expects \n, gets X
    const u8 input[] = "3\r\nabc\rX";
    ChunkedParser p;
    p.reset();
    u8 body[64];
    u32 body_len = 0;
    ChunkStatus s = feed_all(&p, input, 8, body, &body_len);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ChunkStatus::Error));
}

TEST(error, trailer_lf_missing) {
    // "0\r\n\rX" — trailer expects \r\n, but \r followed by non-\n
    const u8 input[] = "0\r\n\rX";
    ChunkedParser p;
    p.reset();
    u32 consumed = 0, out_start = 0, out_len = 0;
    // Feed everything
    u32 offset = 0;
    ChunkStatus s = ChunkStatus::NeedMore;
    while (offset < 5) {
        s = p.feed(input + offset, 5 - offset, &consumed, &out_start, &out_len);
        offset += consumed;
        if (s == ChunkStatus::Error || s == ChunkStatus::Done) break;
    }
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ChunkStatus::Error));
}

TEST(error, trailer_end_lf_missing) {
    // "0\r\n\r\nX" feed after complete → Done
    const u8 input[] = "0\r\n\r\n";
    ChunkedParser p;
    p.reset();
    u8 body[64];
    u32 body_len = 0;
    ChunkStatus s = feed_all(&p, input, 5, body, &body_len);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ChunkStatus::Done));
    // Feed more after completion
    u32 consumed = 0, out_start = 0, out_len = 0;
    const u8 extra[] = "extra data";
    s = p.feed(extra, 10, &consumed, &out_start, &out_len);
    CHECK_EQ(static_cast<u8>(s), static_cast<u8>(ChunkStatus::Done));
}

// ============================================================================

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
