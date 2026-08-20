#include "rut/compiler/rir.h"
#include "rut/runtime/compile_to_config.h"
#include "rut/runtime/route_table.h"
#include "test.h"

using namespace rut;

namespace {

ForwardTargetTransformSpec transform(Str strip, Str replace) {
    return {strip, replace};
}

void make_short_transform(char (&strip)[8], char (&replace)[8], u32 n) {
    const char hex[] = "0123456789abcdef";
    strip[0] = '/';
    strip[1] = 'a';
    strip[2] = hex[n];
    strip[3] = '/';
    replace[0] = '/';
    replace[1] = 'b';
    replace[2] = hex[n];
    replace[3] = '/';
}

void make_full_transform(char (&strip)[129], char (&replace)[129], u32 n) {
    strip[0] = '/';
    replace[0] = '/';
    strip[127] = '/';
    replace[127] = '/';
    for (u32 i = 1; i < 127; i++) {
        strip[i] = 'a';
        replace[i] = 'b';
    }
    strip[1] = static_cast<char>('a' + n);
    replace[1] = static_cast<char>('A' + n);
}

}  // namespace

TEST(target_transform, populate_copies_owned_metadata_and_ids) {
    char strip[] = "/api/";
    char replace[] = "/v1/";
    rir::Module mod{};
    mod.target_transform_count = 1;
    mod.target_transforms[0] = transform({strip, 5}, {replace, 4});

    RouteConfig cfg{};
    REQUIRE(populate_route_config(cfg, mod));
    REQUIRE_EQ(cfg.target_transform_count, 1u);
    CHECK_EQ(cfg.target_transform_bytes_used, 9u);
    CHECK(cfg.target_transform_id_is_valid(1));
    CHECK_FALSE(cfg.target_transform_id_is_valid(0));
    CHECK_FALSE(cfg.target_transform_id_is_valid(2));
    CHECK_FALSE(cfg.target_transform_id_is_valid(kInvalidForwardTargetTransformId));
    CHECK(cfg.target_transforms[0].strip_prefix.ptr != strip);
    CHECK(cfg.target_transforms[0].replace_prefix.ptr != replace);

    strip[1] = 'x';
    replace[1] = 'x';
    CHECK(cfg.target_transforms[0].strip_prefix.eq({"/api/", 5}));
    CHECK(cfg.target_transforms[0].replace_prefix.eq({"/v1/", 4}));
}

TEST(target_transform, duplicate_add_is_stable_and_does_not_consume_storage) {
    char strip[] = "/api/";
    char replace[] = "/v1/";
    char other_strip[] = "/other/";
    char other_replace[] = "/v2/";
    RouteConfig cfg{};
    const auto spec = transform({strip, 5}, {replace, 4});
    REQUIRE_EQ(cfg.add_target_transform(spec), 1u);
    const u32 bytes = cfg.target_transform_bytes_used;
    REQUIRE_EQ(cfg.add_target_transform(transform({"/api/", 5}, {"/v1/", 4})), 1u);
    CHECK_EQ(cfg.target_transform_count, 1u);
    CHECK_EQ(cfg.target_transform_bytes_used, bytes);
    REQUIRE_EQ(cfg.add_target_transform(transform({other_strip, 7}, {other_replace, 4})), 2u);
    CHECK_EQ(cfg.target_transform_count, 2u);
    CHECK_EQ(cfg.target_transform_bytes_used, bytes + 11u);
}

TEST(target_transform, zero_entries_preserve_empty_config) {
    rir::Module mod{};
    RouteConfig cfg{};
    REQUIRE(populate_route_config(cfg, mod));
    CHECK_EQ(cfg.target_transform_count, 0u);
    CHECK_EQ(cfg.target_transform_bytes_used, 0u);
    CHECK_FALSE(cfg.target_transform_id_is_valid(0));
    CHECK_FALSE(cfg.target_transform_id_is_valid(1));
}

TEST(target_transform, rejects_invalid_literals_fail_closed) {
    char no_leading[] = "api/";
    char no_trailing[] = "/api";
    char repeated[] = "/a//";
    char dot[] = "/./";
    char dotdot[] = "/a/../";
    char query[] = "/a?/";
    char fragment[] = "/a#/";
    char percent[] = "/a%/";
    char space[] = "/a b/";
    char control[] = {'/', 'a', '\n', '/'};
    const ForwardTargetTransformSpec invalid[] = {
        transform({no_leading, 4}, {"/ok/", 4}),
        transform({no_trailing, 4}, {"/ok/", 4}),
        transform({repeated, 4}, {"/ok/", 4}),
        transform({dot, 3}, {"/ok/", 4}),
        transform({dotdot, 6}, {"/ok/", 4}),
        transform({query, 4}, {"/ok/", 4}),
        transform({fragment, 4}, {"/ok/", 4}),
        transform({percent, 4}, {"/ok/", 4}),
        transform({space, 5}, {"/ok/", 4}),
        transform({control, 4}, {"/ok/", 4}),
        transform({nullptr, 0}, {"/ok/", 4}),
    };

    RouteConfig cfg{};
    for (const auto& spec : invalid) CHECK_EQ(cfg.add_target_transform(spec), 0u);
    CHECK_EQ(cfg.target_transform_count, 0u);
    CHECK_EQ(cfg.target_transform_bytes_used, 0u);
}

TEST(target_transform, count_and_aggregate_caps_are_bounded) {
    char strips[kMaxForwardTargetTransforms][8];
    char replaces[kMaxForwardTargetTransforms][8];
    RouteConfig count_cfg{};
    for (u32 i = 0; i < kMaxForwardTargetTransforms; i++) {
        make_short_transform(strips[i], replaces[i], i);
        REQUIRE_EQ(count_cfg.add_target_transform(
                       transform({strips[i], 4}, {replaces[i], 4})),
                   i + 1);
    }
    CHECK_EQ(count_cfg.target_transform_count, kMaxForwardTargetTransforms);
    char extra_strip[] = "/extra/";
    char extra_replace[] = "/extra/";
    CHECK_EQ(count_cfg.add_target_transform(transform({extra_strip, 7}, {extra_replace, 7})), 0u);

    char full_strips[9][129];
    char full_replaces[9][129];
    ForwardTargetTransformSpec exact[kMaxForwardTargetTransforms];
    for (u32 i = 0; i < 9; i++) {
        make_full_transform(full_strips[i], full_replaces[i], i);
        exact[i] = transform({full_strips[i], 128}, {full_replaces[i], 128});
    }
    CHECK(forward_target_transform_table_valid(exact, 8));
    CHECK_FALSE(forward_target_transform_table_valid(exact, 9));

    RouteConfig aggregate_cfg{};
    for (u32 i = 0; i < 8; i++)
        REQUIRE_EQ(aggregate_cfg.add_target_transform(exact[i]), i + 1);
    CHECK_EQ(aggregate_cfg.target_transform_bytes_used, kForwardTargetTransformBytes);
    CHECK_EQ(aggregate_cfg.add_target_transform(exact[8]), 0u);
}

TEST(target_transform, adjacent_aggregate_overflow_is_rejected_atomically) {
    char strips[9][129];
    char replaces[9][129];
    ForwardTargetTransformSpec specs[9];
    for (u32 i = 0; i < 8; i++) {
        make_full_transform(strips[i], replaces[i], i);
        specs[i] = transform({strips[i], 128}, {replaces[i], 128});
    }
    // Reduce one valid prefix by one byte, then append the valid one-byte
    // prefixes. The complete table is exactly 2049 bytes, adjacent to the
    // accepted 2048-byte boundary.
    strips[0][126] = '/';
    specs[0].strip_prefix.len = 127;
    strips[8][0] = '/';
    replaces[8][0] = '/';
    specs[8] = transform({strips[8], 1}, {replaces[8], 1});
    for (const auto& spec : specs) CHECK(forward_target_transform_spec_valid(spec));
    CHECK_FALSE(forward_target_transform_table_valid(specs, 9));

    rir::Module mod{};
    mod.target_transform_count = 9;
    for (u32 i = 0; i < 9; i++) mod.target_transforms[i] = specs[i];
    RouteConfig cfg{};
    CHECK_FALSE(populate_route_config(cfg, mod));
    CHECK_EQ(cfg.target_transform_count, 0u);
    CHECK_EQ(cfg.target_transform_bytes_used, 0u);
}

TEST(target_transform, populate_validation_is_atomic) {
    char good_strip[] = "/good/";
    char good_replace[] = "/new/";
    char bad_strip[] = "/bad";
    char bad_replace[] = "/new/";
    rir::Module mod{};
    mod.target_transform_count = 2;
    mod.target_transforms[0] = transform({good_strip, 6}, {good_replace, 5});
    mod.target_transforms[1] = transform({bad_strip, 4}, {bad_replace, 5});

    RouteConfig cfg{};
    CHECK_FALSE(populate_route_config(cfg, mod));
    CHECK_EQ(cfg.target_transform_count, 0u);
    CHECK_EQ(cfg.target_transform_bytes_used, 0u);
}

TEST(target_transform, later_cache_failure_does_not_publish_metadata) {
    char strip[] = "/api/";
    char replace[] = "/v1/";
    rir::Module mod{};
    mod.target_transform_count = 1;
    mod.target_transforms[0] = transform({strip, 5}, {replace, 4});
    mod.cache_instance_count = 1;
    mod.cache_instances[0].name = {nullptr, 1};

    RouteConfig cfg{};
    CHECK_FALSE(populate_route_config(cfg, mod));
    CHECK_EQ(cfg.target_transform_count, 0u);
    CHECK_EQ(cfg.target_transform_bytes_used, 0u);
}

TEST(target_transform, populate_rejects_duplicate_module_ids_atomically) {
    char strip[] = "/api/";
    char replace[] = "/v1/";
    rir::Module mod{};
    mod.target_transform_count = 2;
    mod.target_transforms[0] = transform({strip, 5}, {replace, 4});
    mod.target_transforms[1] = transform({strip, 5}, {replace, 4});
    RouteConfig cfg{};
    CHECK_FALSE(populate_route_config(cfg, mod));
    CHECK_EQ(cfg.target_transform_count, 0u);
    CHECK_EQ(cfg.target_transform_bytes_used, 0u);
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
