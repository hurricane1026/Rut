#include "rut/common/trap.h"
#include "rut/common/types.h"
#include "rut/common/utf8.h"
#include "test.h"

using namespace rut;

namespace {

struct Utf8Case {
    const char* description;
    bool valid;
    u8 size;
    u8 bytes[6];
};

// Boundary cases from Go's TestValid and Rust's from_utf8 tests, grouped by rule.
// https://github.com/golang/go/blob/go1.24.0/src/unicode/utf8/utf8_test.go#L457
// https://github.com/rust-lang/rust/blob/1.85.0/library/alloc/tests/str.rs#L868
constexpr Utf8Case kBoundaryCases[] = {
    {"ASCII with embedded NUL", true, 3, {'A', 0, 'B'}},
    {"last ASCII byte", true, 1, {0x7F}},
    {"first two-byte scalar", true, 2, {0xC2, 0x80}},
    {"last two-byte scalar", true, 2, {0xDF, 0xBF}},
    {"first three-byte scalar", true, 3, {0xE0, 0xA0, 0x80}},
    {"scalar before surrogates", true, 3, {0xED, 0x9F, 0xBF}},
    {"scalar after surrogates", true, 3, {0xEE, 0x80, 0x80}},
    {"last BMP noncharacter", true, 3, {0xEF, 0xBF, 0xBF}},
    {"replacement character", true, 5, {'A', 0xEF, 0xBF, 0xBD, 'B'}},
    {"first supplementary scalar", true, 4, {0xF0, 0x90, 0x80, 0x80}},
    {"last Unicode scalar", true, 4, {0xF4, 0x8F, 0xBF, 0xBF}},
    {"first high surrogate", false, 3, {0xED, 0xA0, 0x80}},
    {"last low surrogate", false, 3, {0xED, 0xBF, 0xBF}},
    {"UTF-16 surrogate pair encoded as CESU-8", false, 6, {0xED, 0xA0, 0x80, 0xED, 0xB0, 0x80}},
    {"above Unicode maximum", false, 4, {0xF4, 0x90, 0x80, 0x80}},
    {"obsolete five-byte form", false, 5, {0xF8, 0x88, 0x80, 0x80, 0x80}},
    {"obsolete six-byte form", false, 6, {0xFC, 0x84, 0x80, 0x80, 0x80, 0x80}},
    {"overlong NUL", false, 2, {0xC0, 0x80}},
    {"overlong U+07FF", false, 3, {0xE0, 0x9F, 0xBF}},
    {"overlong U+FFFF", false, 4, {0xF0, 0x8F, 0xBF, 0xBF}},
    {"malformed suffix after embedded NUL", false, 4, {'A', 0, 0xFA, 'B'}},
};

[[nodiscard]] constexpr u8 continuation(u32 payload) {
    return (range_int<0x80, 0x81>{} + bounded_remainder<64>(payload)).to<u8>();
}
[[nodiscard]] constexpr u8 byte(u32 value) {
    range_int<0, 256> checked;
    if (!decltype(checked)::try_from_u64(value, &checked))
        RUT_TRAP("UTF-8 test byte exceeds its range");
    return checked.to<u8>();
}

}  // namespace

TEST(utf8, empty_and_null_inputs) {
    const u8 kByte = 0;
    CHECK(utf8_valid(nullptr, 0));
    CHECK(utf8_valid(&kByte, 0));
    CHECK_FALSE(utf8_valid(nullptr, 1));
}

TEST(utf8, boundary_cases) {
    for (const auto& input : kBoundaryCases) {
        CHECK_MSG(utf8_valid(input.bytes, input.size) == input.valid, input.description);
    }
}

TEST(utf8, every_single_byte) {
    for (u32 value = 0; value < 0x100; ++value) {
        const u8 kByte = byte(value);
        REQUIRE_EQ(utf8_valid(&kByte, 1), value < 0x80);
    }
}

TEST(utf8, every_multibyte_payload) {
    // Enumerate all sequences with the corresponding lead and continuation bit
    // patterns. RFC 3629 defines which payloads are legal for each width.
    // https://www.rfc-editor.org/rfc/rfc3629#section-4
    for (u32 cp = 0; cp < 0x800; ++cp) {
        const u8 kBytes[] = {byte(0xC0 | (cp >> 6)), continuation(cp)};
        REQUIRE_EQ(utf8_valid(kBytes, sizeof(kBytes)), cp >= 0x80);
    }
    for (u32 cp = 0; cp < 0x10000; ++cp) {
        const u8 kBytes[] = {byte(0xE0 | (cp >> 12)), continuation(cp >> 6), continuation(cp)};
        const bool kSurrogate = cp >= 0xD800 && cp <= 0xDFFF;
        REQUIRE_EQ(utf8_valid(kBytes, sizeof(kBytes)), cp >= 0x800 && !kSurrogate);
    }
    for (u32 cp = 0; cp < 0x200000; ++cp) {
        const u8 kBytes[] = {byte(0xF0 | (cp >> 18)),
                             continuation(cp >> 12),
                             continuation(cp >> 6),
                             continuation(cp)};
        REQUIRE_EQ(utf8_valid(kBytes, sizeof(kBytes)), cp >= 0x10000 && cp <= 0x10FFFF);
    }
}

TEST(utf8, truncated_sequences_in_exact_size_buffers) {
    const u8 kTwoByte[] = {0xC2};
    const u8 kThreeByte[] = {0xE2, 0x82};
    const u8 kFourByte[] = {0xF0, 0x9F, 0x99};
    CHECK_FALSE(utf8_valid(kTwoByte, sizeof(kTwoByte)));
    CHECK_FALSE(utf8_valid(kThreeByte, sizeof(kThreeByte)));
    CHECK_FALSE(utf8_valid(kFourByte, sizeof(kFourByte)));
}

TEST(utf8, truncation_and_invalid_continuations_after_valid_prefix) {
    // Vary error positions in otherwise valid text, as in simdutf's corruption tests.
    // https://github.com/simdutf/simdutf/blob/v8.2.0/tests/validate_utf8_brute_force_tests.cpp
    constexpr u8 kPrefix[] = {'A', 0xC3, 0xA9, 0xE4, 0xB8, 0xAD, 0};
    constexpr u8 kScalar[] = {0xF0, 0x9F, 0x99, 0x82};
    constexpr u64 kMaxOffset = 257;
    constexpr u64 kOffsets[] = {
        sizeof(kPrefix), 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, kMaxOffset};
    constexpr u8 kInvalidContinuations[] = {0x00, 0x7F, 0xC0, 0xFF};
    for (const u64 kOffset : kOffsets) {
        u8 bytes[kMaxOffset + sizeof(kScalar) + 1] = {};
        __builtin_memcpy(bytes, kPrefix, sizeof(kPrefix));
        for (u64 i = sizeof(kPrefix); i < kOffset; ++i) bytes[i] = 'a';
        auto* scalar = bytes + kOffset;
        __builtin_memcpy(scalar, kScalar, sizeof(kScalar));
        const u64 kCompleteLength = kOffset + sizeof(kScalar) + 1;
        REQUIRE(utf8_valid(bytes, kCompleteLength));
        for (u64 i = 1; i < sizeof(kScalar); ++i) {
            REQUIRE_FALSE(utf8_valid(bytes, kOffset + i));
            for (const u8 kInvalid : kInvalidContinuations) {
                scalar[i] = kInvalid;
                REQUIRE_FALSE(utf8_valid(bytes, kCompleteLength));
            }
            scalar[i] = kScalar[i];
        }
    }
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
