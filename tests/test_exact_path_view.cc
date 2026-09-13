#include "rut/common/exact_path_view.h"
#include "test.h"

using namespace rut;

namespace {

bool normalized_equals(Str raw, Str expected) {
    char output[kMaxExactPathViewLen]{};
    u32 output_len = 999;
    if (normalize_exact_path_slashes(raw, output, sizeof(output), &output_len) !=
            ExactPathNormalizationResult::Success ||
        output_len != expected.len)
        return false;
    return (Str{output, output_len}).eq(expected);
}

bool failure_leaves_output_unchanged(Str raw,
                                     ExactPathNormalizationResult expected,
                                     u32 capacity = kMaxExactPathViewLen) {
    char output[kMaxExactPathViewLen];
    for (u32 i = 0; i < sizeof(output); i++) output[i] = static_cast<char>(0x5a);
    u32 output_len = 31337;
    if (normalize_exact_path_slashes(raw, output, capacity, &output_len) != expected ||
        output_len != 31337u)
        return false;
    for (u32 i = 0; i < sizeof(output); i++)
        if (output[i] != static_cast<char>(0x5a)) return false;
    return true;
}

}  // namespace

TEST(exact_path_view, enum_is_one_byte_and_raw_is_zero) {
    CHECK_EQ(sizeof(ExactPathView), sizeof(u8));
    CHECK_EQ(static_cast<u8>(ExactPathView::Raw), 0u);
    CHECK_EQ(static_cast<u8>(ExactPathView::SlashNormalized), 1u);
    CHECK_EQ(kMaxExactPathViewLen, 62u);
}

TEST(exact_path_view, root_and_query_boundary) {
    CHECK(normalized_equals(lit_str("/"), lit_str("/")));
    CHECK(normalized_equals(lit_str("/?x=//not-path#also-not-path"), lit_str("/")));
    CHECK(normalized_equals(lit_str("/health//check///?x=//"), lit_str("/health/check/")));

    const char query_control[] = {'/', 'o', 'k', '?', '\x01'};
    CHECK(normalized_equals({query_control, sizeof(query_control)}, lit_str("/ok")));
}

TEST(exact_path_view, collapses_embedded_and_trailing_runs_but_preserves_identity) {
    CHECK(normalized_equals(lit_str("/health/check"), lit_str("/health/check")));
    CHECK(normalized_equals(lit_str("/health/check/"), lit_str("/health/check/")));
    CHECK(normalized_equals(lit_str("/health/check//"), lit_str("/health/check/")));
    CHECK(normalized_equals(lit_str("/a//b///c/"), lit_str("/a/b/c/")));
    CHECK(normalized_equals(lit_str("/a//b///c////"), lit_str("/a/b/c/")));
}

TEST(exact_path_view, percent_and_dot_segments_are_opaque) {
    CHECK(normalized_equals(lit_str("/a/%2F/./../b"), lit_str("/a/%2F/./../b")));
    CHECK(normalized_equals(lit_str("/a//%2f//..//"), lit_str("/a/%2f/../")));
}

TEST(exact_path_view, rejects_non_origin_leading_runs_fragment_and_controls) {
    CHECK(
        failure_leaves_output_unchanged({nullptr, 0}, ExactPathNormalizationResult::InvalidInput));
    CHECK(
        failure_leaves_output_unchanged({nullptr, 1}, ExactPathNormalizationResult::InvalidInput));
    CHECK(failure_leaves_output_unchanged({"", 0}, ExactPathNormalizationResult::InvalidInput));
    CHECK(failure_leaves_output_unchanged(lit_str("?x=1"),
                                          ExactPathNormalizationResult::InvalidInput));
    CHECK(
        failure_leaves_output_unchanged(lit_str("*"), ExactPathNormalizationResult::InvalidInput));
    CHECK(failure_leaves_output_unchanged(lit_str("example.test:443"),
                                          ExactPathNormalizationResult::InvalidInput));
    CHECK(failure_leaves_output_unchanged(lit_str("//health"),
                                          ExactPathNormalizationResult::InvalidInput));
    CHECK(failure_leaves_output_unchanged(lit_str("///?x=1"),
                                          ExactPathNormalizationResult::InvalidInput));
    CHECK(failure_leaves_output_unchanged(lit_str("/health#fragment"),
                                          ExactPathNormalizationResult::InvalidInput));

    const char control[] = {'/', 'a', '\x1f', 'b'};
    const char del[] = {'/', 'a', '\x7f', 'b'};
    CHECK(failure_leaves_output_unchanged({control, sizeof(control)},
                                          ExactPathNormalizationResult::InvalidInput));
    CHECK(failure_leaves_output_unchanged({del, sizeof(del)},
                                          ExactPathNormalizationResult::InvalidInput));
}

TEST(exact_path_view, bound_accepts_62_and_rejects_63_transactionally) {
    char exact[kMaxExactPathViewLen];
    exact[0] = '/';
    for (u32 i = 1; i < sizeof(exact); i++) exact[i] = 'a';
    CHECK(normalized_equals({exact, sizeof(exact)}, {exact, sizeof(exact)}));

    char too_long[kMaxExactPathViewLen + 1];
    too_long[0] = '/';
    for (u32 i = 1; i < sizeof(too_long); i++) too_long[i] = 'b';
    CHECK(failure_leaves_output_unchanged({too_long, sizeof(too_long)},
                                          ExactPathNormalizationResult::OutputOverflow));
    CHECK(failure_leaves_output_unchanged(
        lit_str("/abc"), ExactPathNormalizationResult::OutputOverflow, 3));
}

TEST(exact_path_view, long_raw_slash_run_may_normalize_within_bound) {
    char raw[256];
    raw[0] = '/';
    raw[1] = 'a';
    for (u32 i = 2; i < 254; i++) raw[i] = '/';
    raw[254] = 'b';
    raw[255] = '/';
    CHECK(normalized_equals({raw, sizeof(raw)}, lit_str("/a/b/")));
}

TEST(exact_path_view, input_is_never_mutated) {
    char raw[] = "/a//b///?q=//";
    char before[sizeof(raw)];
    for (u32 i = 0; i < sizeof(raw); i++) before[i] = raw[i];
    CHECK(normalized_equals({raw, sizeof(raw) - 1}, lit_str("/a/b/")));
    for (u32 i = 0; i < sizeof(raw); i++) CHECK_EQ(raw[i], before[i]);

    u32 aliased_len = 99;
    CHECK(normalize_exact_path_slashes({raw, sizeof(raw) - 1}, raw, sizeof(raw), &aliased_len) ==
          ExactPathNormalizationResult::InvalidInput);
    CHECK_EQ(aliased_len, 99u);
    for (u32 i = 0; i < sizeof(raw); i++) CHECK_EQ(raw[i], before[i]);
}

TEST(exact_path_view, invalid_destination_arguments_do_not_read_or_write) {
    char output[kMaxExactPathViewLen]{};
    u32 output_len = 7;
    CHECK(normalize_exact_path_slashes(lit_str("/ok"), nullptr, sizeof(output), &output_len) ==
          ExactPathNormalizationResult::InvalidInput);
    CHECK(normalize_exact_path_slashes(lit_str("/ok"), output, sizeof(output), nullptr) ==
          ExactPathNormalizationResult::InvalidInput);
    CHECK_EQ(output_len, 7u);
}

TEST(exact_path_view, rejects_overflowing_raw_range_before_dereference) {
    char output[kMaxExactPathViewLen];
    for (u32 i = 0; i < sizeof(output); i++) output[i] = static_cast<char>(0x5a);
    u32 output_len = 0x12345678u;
    const Str overflowing_raw{reinterpret_cast<const char*>(UINTPTR_MAX - uintptr_t{1}), 3};

    CHECK(normalize_exact_path_slashes(overflowing_raw, output, sizeof(output), &output_len) ==
          ExactPathNormalizationResult::InvalidInput);
    CHECK_EQ(output_len, 0x12345678u);
    for (u32 i = 0; i < sizeof(output); i++) CHECK_EQ(output[i], static_cast<char>(0x5a));
}

TEST(exact_path_view, zero_output_capacity_is_transactional) {
    char raw[] = "/a//b";
    char raw_before[sizeof(raw)];
    for (u32 i = 0; i < sizeof(raw); i++) raw_before[i] = raw[i];
    char output[kMaxExactPathViewLen];
    for (u32 i = 0; i < sizeof(output); i++) output[i] = static_cast<char>(0x5a);
    u32 output_len = 0x12345678u;

    CHECK(normalize_exact_path_slashes({raw, sizeof(raw) - 1u}, output, 0, &output_len) ==
          ExactPathNormalizationResult::OutputOverflow);
    CHECK_EQ(output_len, 0x12345678u);
    for (u32 i = 0; i < sizeof(raw); i++) CHECK_EQ(raw[i], raw_before[i]);
    for (u32 i = 0; i < sizeof(output); i++) CHECK_EQ(output[i], static_cast<char>(0x5a));
}

TEST(exact_path_view, rejects_output_length_overlapping_raw_transactionally) {
    alignas(u32) char storage[16];
    for (u32 i = 0; i < sizeof(storage); i++) storage[i] = static_cast<char>(0x33);
    constexpr char kRaw[] = "/a//b///";
    for (u32 i = 0; i < sizeof(kRaw) - 1u; i++) storage[i + 2u] = kRaw[i];
    char storage_before[sizeof(storage)];
    for (u32 i = 0; i < sizeof(storage); i++) storage_before[i] = storage[i];
    char output[kMaxExactPathViewLen];
    for (u32 i = 0; i < sizeof(output); i++) output[i] = static_cast<char>(0x5a);
    // The length object's address precedes raw, but its full four-byte range
    // overlaps raw by two bytes.
    auto* const aliased_len = reinterpret_cast<u32*>(storage);

    CHECK(normalize_exact_path_slashes(
              {storage + 2u, sizeof(kRaw) - 1u}, output, sizeof(output), aliased_len) ==
          ExactPathNormalizationResult::InvalidInput);
    for (u32 i = 0; i < sizeof(storage); i++) CHECK_EQ(storage[i], storage_before[i]);
    for (u32 i = 0; i < sizeof(output); i++) CHECK_EQ(output[i], static_cast<char>(0x5a));
}

TEST(exact_path_view, rejects_output_length_overlapping_output_transactionally) {
    char raw[] = "/a//b///";
    char raw_before[sizeof(raw)];
    for (u32 i = 0; i < sizeof(raw); i++) raw_before[i] = raw[i];
    alignas(u32) char storage[kMaxExactPathViewLen + 2u];
    for (u32 i = 0; i < sizeof(storage); i++) storage[i] = static_cast<char>(0x5a);
    char output_before[sizeof(storage)];
    for (u32 i = 0; i < sizeof(storage); i++) output_before[i] = storage[i];
    // The length object's address precedes output, but its full four-byte range
    // overlaps the normalized output write range by two bytes.
    char* const output = storage + 2u;
    auto* const aliased_len = reinterpret_cast<u32*>(storage);

    CHECK(normalize_exact_path_slashes(
              {raw, sizeof(raw) - 1u}, output, kMaxExactPathViewLen, aliased_len) ==
          ExactPathNormalizationResult::InvalidInput);
    for (u32 i = 0; i < sizeof(raw); i++) CHECK_EQ(raw[i], raw_before[i]);
    for (u32 i = 0; i < sizeof(storage); i++) CHECK_EQ(storage[i], output_before[i]);
}

TEST(exact_path_view, rejects_overflowing_output_length_range_before_write) {
    char raw[] = "/a//b";
    char raw_before[sizeof(raw)];
    for (u32 i = 0; i < sizeof(raw); i++) raw_before[i] = raw[i];
    char output[kMaxExactPathViewLen];
    for (u32 i = 0; i < sizeof(output); i++) output[i] = static_cast<char>(0x5a);
    auto* const overflowing_len = reinterpret_cast<u32*>(UINTPTR_MAX - uintptr_t{1});

    CHECK(normalize_exact_path_slashes(
              {raw, sizeof(raw) - 1u}, output, sizeof(output), overflowing_len) ==
          ExactPathNormalizationResult::InvalidInput);
    for (u32 i = 0; i < sizeof(raw); i++) CHECK_EQ(raw[i], raw_before[i]);
    for (u32 i = 0; i < sizeof(output); i++) CHECK_EQ(output[i], static_cast<char>(0x5a));
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
