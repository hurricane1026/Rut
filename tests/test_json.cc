#include "rut/runtime/json.h"
#include "test.h"

using namespace rut;

TEST(json, valid_values_and_lossless_numbers) {
    json::Document d;
    const Str values[] = {lit_str("null"),
                          lit_str("true"),
                          lit_str("false"),
                          lit_str("0"),
                          lit_str("-0"),
                          lit_str("1.25e+300"),
                          lit_str("1e999999"),
                          lit_str("9223372036854775808"),
                          lit_str("[]"),
                          lit_str("{}"),
                          lit_str(" { \"nested\": [null, false, {\"x\": -12.5e-4}] } ")};
    for (auto s : values) CHECK(d.parse(s));
    i64 value = 0;
    CHECK(json::integer(lit_str("9223372036854775807"), value));
    CHECK_EQ(value, 9223372036854775807LL);
    CHECK(json::integer(lit_str("-9223372036854775808"), value));
    CHECK_EQ(value, (-9223372036854775807LL - 1));
    CHECK(!json::integer(lit_str("9223372036854775808"), value));
    CHECK(!json::integer(lit_str("-9223372036854775809"), value));
    CHECK(!json::integer(lit_str("1e0"), value));
}

TEST(json, malformed_grammar_and_ambiguous_members) {
    json::Document d;
    const Str bad[] = {lit_str(""),
                       lit_str(" "),
                       lit_str("+1"),
                       lit_str("01"),
                       lit_str("-01"),
                       lit_str(".1"),
                       lit_str("1."),
                       lit_str("1e"),
                       lit_str("1e+"),
                       lit_str("NaN"),
                       lit_str("Infinity"),
                       lit_str("[1,]"),
                       lit_str("[,1]"),
                       lit_str("{\"a\":1,}"),
                       lit_str("{a:1}"),
                       lit_str("{}{}"),
                       lit_str("true false"),
                       lit_str("/*x*/1"),
                       lit_str("\"a\n\""),
                       lit_str("\"\\x41\""),
                       lit_str("\"\\uD800\""),
                       lit_str("\"\\uDC00\""),
                       lit_str("\"\\uD800\\u0041\""),
                       lit_str("\"\\u000\""),
                       lit_str("{\"a\":1,\"\\u0061\":2}")};
    for (auto s : bad) CHECK(!d.parse(s));
    const char invalid_utf8[][6] = {{'"', char(0xc0), char(0xaf), '"', 0},
                                    {'"', char(0xed), char(0xa0), char(0x80), '"', 0},
                                    {'"', char(0xf4), char(0x90), char(0x80), char(0x80), '"'}};
    CHECK(!d.parse({invalid_utf8[0], 4}));
    CHECK(!d.parse({invalid_utf8[1], 5}));
    CHECK(!d.parse({invalid_utf8[2], 6}));
}

TEST(json, unicode_escapes_and_roundtrip) {
    json::Document d;
    REQUIRE(d.parse(lit_str(" {\"x\":\"\\uD83D\\uDE00\\u0000\\n\\t\\\\\\\"\\/\", \"n\":1e999} ")));
    char output[json::kMaxBytes];
    json::Writer w{output};
    REQUIRE(d.write(0, w));
    const Str expected = lit_str("{\"x\":\"😀\\u0000\\u000a\\u0009\\\\\\\"/\",\"n\":1e999}");
    CHECK((Str{output, w.len}.eq(expected)));
    REQUIRE(d.parse({output, w.len}));
    const u32 x = d.pointer(lit_str("/x"));
    REQUIRE(x != json::kNone);
    char decoded[json::kMaxBytes];
    json::Writer text{decoded};
    REQUIRE(d.string(x, text));
    CHECK_EQ(text.len, 10u);
    CHECK_EQ(decoded[4], '\0');
}

TEST(json, pointer_null_missing_and_array_indices) {
    json::Document d;
    REQUIRE(d.parse(lit_str("{\"\":0,\"a/b\":{\"~key\":[null,false]},\"01\":7}")));
    CHECK_EQ(d.pointer(lit_str("")), 0u);
    CHECK(d.pointer(lit_str("/")) != json::kNone);
    const u32 n = d.pointer(lit_str("/a~1b/~0key/0"));
    REQUIRE(n != json::kNone);
    CHECK_EQ(d.nodes[n].kind, json::Kind::Null);
    CHECK_EQ(d.pointer(lit_str("/missing")), json::kNone);
    CHECK_EQ(d.pointer(lit_str("/a~1b/~0key/01")), json::kNone);
    CHECK_EQ(d.pointer(lit_str("/a~1b/~0key/-")), json::kNone);
    CHECK_EQ(d.pointer(lit_str("/a~1b/~0key/4294967296")), json::kNone);
    CHECK_EQ(d.pointer(lit_str("/bad~2")), json::kNone);
    CHECK_EQ(d.pointer(lit_str("#")), json::kNone);
}

TEST(json, immutable_edits_and_keys) {
    json::Document d;
    char output[json::kMaxBytes];
    Str view{};
    i64 number = 0;
    auto check = [&](json::Op op, Str a, Str b, Str c, Str expected) {
        json::Writer w{output};
        const bool ok = json::apply(d, op, a, b, c, 0, w, view, number);
        CHECK(ok);
        if (ok) CHECK((Str{output, w.len}.eq(expected)));
    };
    const Str input = lit_str("{\"x\":[1,null],\"a\":true}");
    check(json::Op::Set,
          input,
          lit_str("/x/0"),
          lit_str("2"),
          lit_str("{\"x\":[2,null],\"a\":true}"));
    check(json::Op::Remove, input, lit_str("/x/0"), {}, lit_str("{\"x\":[null],\"a\":true}"));
    check(json::Op::Append,
          input,
          lit_str("/x"),
          lit_str("false"),
          lit_str("{\"x\":[1,null,false],\"a\":true}"));
    check(json::Op::Member,
          input,
          lit_str("a"),
          lit_str("null"),
          lit_str("{\"x\":[1,null],\"a\":null}"));
    check(json::Op::Member,
          input,
          lit_str("b"),
          lit_str("{}"),
          lit_str("{\"x\":[1,null],\"a\":true,\"b\":{}}"));
    check(json::Op::Keys, input, {}, {}, lit_str("[\"x\",\"a\"]"));
    json::Writer w{output};
    CHECK(!json::apply(d, json::Op::Remove, input, lit_str(""), {}, 0, w, view, number));
}

TEST(json, resource_limits_fail_closed) {
    json::Document d;
    char nested[2 * (json::kMaxDepth + 2) + 1];
    u32 p = 0;
    for (u32 i = 0; i < json::kMaxDepth + 2; ++i) nested[p++] = '[';
    nested[p++] = '0';
    for (u32 i = 0; i < json::kMaxDepth + 2; ++i) nested[p++] = ']';
    CHECK(!d.parse({nested, p}));
    char many[json::kMaxBytes + 1];
    for (u32 i = 0; i < sizeof(many); ++i) many[i] = ' ';
    CHECK(!d.parse({many, sizeof(many)}));
    p = 0;
    many[p++] = '[';
    for (u32 i = 0; i < json::kMaxNodes; ++i) {
        if (i) many[p++] = ',';
        many[p++] = '0';
    }
    many[p++] = ']';
    CHECK(!d.parse({many, p}));
    json::Writer w{many};
    for (u32 i = 0; i < json::kMaxBytes; ++i) w.put('x');
    CHECK(w.ok);
    w.put('x');
    CHECK(!w.ok);
}

TEST(json, scalar_conversions_reject_coercion_and_integer_overflow) {
    json::Document document;
    char output[json::kMaxBytes];
    struct Case {
        json::Op op;
        Str input;
        bool ok;
        i64 value;
    };
    const Case cases[] = {
        {json::Op::AsI32, lit_str("-2147483648"), true, -2147483648LL},
        {json::Op::AsI32, lit_str("2147483647"), true, 2147483647LL},
        {json::Op::AsI32, lit_str("-2147483649"), false, 0},
        {json::Op::AsI32, lit_str("2147483648"), false, 0},
        {json::Op::AsInt, lit_str("-9223372036854775808"), true, -9223372036854775807LL - 1},
        {json::Op::AsInt, lit_str("9223372036854775807"), true, 9223372036854775807LL},
        {json::Op::AsInt, lit_str("9223372036854775808"), false, 0},
        {json::Op::AsInt, lit_str("-9223372036854775809"), false, 0},
        {json::Op::AsInt, lit_str("1.0"), false, 0},
        {json::Op::AsInt, lit_str("1e0"), false, 0},
        {json::Op::AsInt, lit_str("\"1\""), false, 0},
        {json::Op::AsInt, lit_str("true"), false, 0},
        {json::Op::AsBool, lit_str("false"), true, 0},
        {json::Op::AsBool, lit_str("true"), true, 1},
        {json::Op::AsBool, lit_str("0"), false, 0},
        {json::Op::AsBool, lit_str("\"false\""), false, 0},
        {json::Op::AsBool, lit_str("null"), false, 0},
        {json::Op::AsInt, lit_str("-0"), true, 0},
    };
    for (const auto& c : cases) {
        json::Writer writer{output};
        Str view{};
        i64 scalar = 123;
        const bool ok = json::apply(document, c.op, c.input, {}, {}, 0, writer, view, scalar);
        CHECK_EQ(ok, c.ok);
        if (ok) CHECK_EQ(scalar, c.value);
    }
}

TEST(json, failed_parse_does_not_poison_next_document) {
    json::Document document;
    const Str malformed[] = {lit_str("{\"old\":[1,2,"),
                             lit_str("{\"x\":1,\"x\":2}"),
                             lit_str("\"\\uD800\""),
                             lit_str("[true] trailing")};
    for (auto input : malformed) {
        REQUIRE(document.parse(lit_str("{\"old\":[1,2,3]}")));
        CHECK(!document.parse(input));
        REQUIRE(document.parse(lit_str("{\"new\":[false,null]}")));
        CHECK_EQ(document.pointer(lit_str("/old")), json::kNone);
        const u32 value = document.pointer(lit_str("/new/0"));
        REQUIRE(value != json::kNone);
        CHECK_EQ(document.nodes[value].kind, json::Kind::Boolean);
        CHECK(document.raw(value).eq(lit_str("false")));
        char output[json::kMaxBytes];
        json::Writer writer{output};
        REQUIRE(document.write(0, writer));
        CHECK((Str{output, writer.len}.eq(lit_str("{\"new\":[false,null]}"))));
    }
}
TEST(json, edits_preserve_siblings_and_escape_member_names) {
    struct Case {
        json::Op op;
        Str input;
        Str path;
        Str value;
        Str expected;
    };
    const Case cases[] = {
        {json::Op::Set,
         lit_str(R"({"a/b":{"~":[1,2,3]},"keep":true})"),
         lit_str("/a~1b/~0/1"),
         lit_str("null"),
         lit_str(R"({"a/b":{"~":[1,null,3]},"keep":true})")},
        {json::Op::Remove, lit_str("[1,2,3]"), lit_str("/0"), {}, lit_str("[2,3]")},
        {json::Op::Remove, lit_str("[1,2,3]"), lit_str("/1"), {}, lit_str("[1,3]")},
        {json::Op::Remove, lit_str("[1,2,3]"), lit_str("/2"), {}, lit_str("[1,2]")},
        {json::Op::Remove, lit_str(R"({"only":null})"), lit_str("/only"), {}, lit_str("{}")},
        {json::Op::Set,
         lit_str(R"({"old":1})"),
         lit_str(""),
         lit_str("[false]"),
         lit_str("[false]")},
        {json::Op::Append,
         lit_str(R"({"a":[],"b":2})"),
         lit_str("/a"),
         lit_str(R"({"x":1})"),
         lit_str(R"({"a":[{"x":1}],"b":2})")},
        {json::Op::Member,
         lit_str(R"({"\u0061":1,"b":2})"),
         lit_str("a"),
         lit_str("3"),
         lit_str(R"({"a":3,"b":2})")},
        {json::Op::Member,
         lit_str("{}"),
         lit_str("a\"\n"),
         lit_str("false"),
         lit_str(R"({"a\"\u000a":false})")},
        {json::Op::Element, lit_str("[]"), lit_str("null"), {}, lit_str("[null]")},
        {json::Op::Keys, lit_str(R"({"b":1,"a/b":2,"":3})"), {}, {}, lit_str(R"(["b","a/b",""])")},
    };
    json::Document document;
    for (const auto& c : cases) {
        char input[json::kMaxBytes];
        __builtin_memcpy(input, c.input.ptr, c.input.len);
        char output[json::kMaxBytes];
        json::Writer writer{output};
        Str view{};
        i64 scalar = 0;
        REQUIRE(json::apply(
            document, c.op, {input, c.input.len}, c.path, c.value, 0, writer, view, scalar));
        CHECK((Str{output, writer.len}.eq(c.expected)));
        CHECK((Str{input, c.input.len}.eq(c.input)));
        REQUIRE(document.parse({output, writer.len}));
    }
}

TEST(json, invalid_edits_and_indices_fail_without_coercion) {
    struct Case {
        json::Op op;
        Str input;
        Str path;
        Str value;
        i64 index;
    };
    const Case cases[] = {
        {json::Op::Set, lit_str("{}"), lit_str("/missing"), lit_str("0"), 0},
        {json::Op::Set, lit_str("[0]"), lit_str("/1"), lit_str("0"), 0},
        {json::Op::Set, lit_str("[0]"), lit_str("/01"), lit_str("0"), 0},
        {json::Op::Set, lit_str("[0]"), lit_str("/-"), lit_str("0"), 0},
        {json::Op::Set, lit_str("[0]"), lit_str("/0"), lit_str("{"), 0},
        {json::Op::Set, lit_str("[0]"), lit_str("/0"), lit_str(R"({"x":1,"x":2})"), 0},
        {json::Op::Append, lit_str(R"({"a":null})"), lit_str("/a"), lit_str("0"), 0},
        {json::Op::Append, lit_str("[]"), lit_str(""), lit_str("true false"), 0},
        {json::Op::Member, lit_str("[]"), lit_str("x"), lit_str("0"), 0},
        {json::Op::Element, lit_str("{}"), lit_str("0"), {}, 0},
        {json::Op::Remove, lit_str("[0]"), lit_str("/2"), {}, 0},
        {json::Op::Get, lit_str(R"({"a":0})"), lit_str("/a/child"), {}, 0},
        {json::Op::Get, lit_str(R"({"a":0})"), lit_str("/bad~"), {}, 0},
        {json::Op::At, lit_str("[1]"), {}, {}, -1},
        {json::Op::At, lit_str("[1]"), {}, {}, 1},
        {json::Op::At, lit_str("[1]"), {}, {}, 4294967296LL},
        {json::Op::At, lit_str(R"({"0":1})"), {}, {}, 0},
        {json::Op::Count, lit_str("null"), {}, {}, 0},
        {json::Op::Keys, lit_str("[1]"), {}, {}, 0},
        {json::Op::AsString, lit_str("123"), {}, {}, 0},
        {json::Op::RequireObject, lit_str("[]"), {}, {}, 0},
    };
    json::Document document;
    for (const auto& c : cases) {
        char output[json::kMaxBytes];
        json::Writer writer{output};
        Str view = lit_str("stale");
        i64 scalar = 0;
        CHECK(
            !json::apply(document, c.op, c.input, c.path, c.value, c.index, writer, view, scalar));
        CHECK(view.ptr == nullptr);
    }
}

TEST(json, exact_byte_node_and_depth_budgets) {
    json::Document document;
    char input[json::kMaxBytes + 1];
    input[0] = '"';
    for (u32 i = 1; i < json::kMaxBytes - 1; ++i) input[i] = 'a';
    input[json::kMaxBytes - 1] = '"';
    REQUIRE(document.parse({input, json::kMaxBytes}));
    input[json::kMaxBytes] = ' ';
    CHECK(!document.parse({input, json::kMaxBytes + 1}));

    // The root array consumes one node; each scalar consumes one more.
    u32 len = 0;
    input[len++] = '[';
    for (u32 i = 0; i < json::kMaxNodes - 1; ++i) {
        if (i) input[len++] = ',';
        input[len++] = '0';
    }
    input[len++] = ']';
    REQUIRE(document.parse({input, len}));
    CHECK_EQ(document.count, json::kMaxNodes);
    input[len - 1] = ',';
    input[len++] = '0';
    input[len++] = ']';
    CHECK(!document.parse({input, len}));

    for (u32 depth = json::kMaxDepth; depth <= json::kMaxDepth + 1; ++depth) {
        len = 0;
        for (u32 i = 0; i < depth; ++i) input[len++] = '[';
        input[len++] = '0';
        for (u32 i = 0; i < depth; ++i) input[len++] = ']';
        CHECK_EQ(document.parse({input, len}), depth == json::kMaxDepth);
    }
    REQUIRE(document.parse(lit_str("null")));
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
