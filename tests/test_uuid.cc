#include "rut/runtime/uuid.h"
#include "test.h"

using namespace rut;

TEST(uuid, rfc9562_version_variant_and_lowercase_vectors) {
    struct Case {
        u8 fill;
        const char* expected;
    } cases[] = {
        {0, "00000000-0000-4000-8000-000000000000"},
        {255, "ffffffff-ffff-4fff-bfff-ffffffffffff"},
    };
    for (const auto& test : cases) {
        char text[kUuidTextLength];
        u32 calls = 0;
        REQUIRE(generate_uuid(text, [&](u8* bytes, u32 size) -> i32 {
            ++calls;
            CHECK_EQ(size, 16u);
            for (u32 i = 0; i < size; ++i) bytes[i] = test.fill;
            return static_cast<i32>(size);
        }));
        CHECK_EQ(calls, 1u);
        CHECK((Str{text, sizeof(text)}.eq({test.expected, kUuidTextLength})));
    }
    char text[kUuidTextLength];
    REQUIRE(generate_uuid(text, [](u8* bytes, u32 size) -> i32 {
        for (u32 i = 0; i < size; ++i) bytes[i] = static_cast<u8>(i);
        return static_cast<i32>(size);
    }));
    CHECK((Str{text, sizeof(text)}.eq(lit_str("00010203-0405-4607-8809-0a0b0c0d0e0f"))));
}

TEST(uuid, failed_or_short_entropy_never_publishes_partial_output_or_retries) {
    const i32 results[] = {-1, 0, 1, 15};
    for (i32 result : results) {
        char text[kUuidTextLength];
        for (char& ch : text) ch = '!';
        u32 calls = 0;
        CHECK(!generate_uuid(text, [&](u8* bytes, u32 size) -> i32 {
            ++calls;
            for (u32 i = 0; i < size; ++i) bytes[i] = 0xff;
            return result;
        }));
        CHECK_EQ(calls, 1u);
        for (char ch : text) CHECK_EQ(ch, '!');
    }
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
