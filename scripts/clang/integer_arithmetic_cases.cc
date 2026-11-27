#include "rut/common/checked_arithmetic.h"
#include "rut/common/range_int.h"

using namespace rut;

int signed_add(int a, int b) {
    return a + b;  // expected-warning {{integer arithmetic needs a range proof}}
}

unsigned unsigned_sub(unsigned a, unsigned b) {
    return a - b;  // expected-warning {{integer arithmetic needs a range proof}}
}

unsigned compound_product(unsigned a, unsigned b) {
    a *= b;  // expected-warning {{integer arithmetic needs a range proof}}
    return a;
}

unsigned char narrow_assignment(unsigned char a) {
    a += 1;  // expected-warning {{integer arithmetic needs a range proof}}
    return a;
}

int decrement(int a) {
    return --a;  // expected-warning {{integer arithmetic needs a range proof}}
}

int negate(int a) {
    return -a;  // expected-warning {{integer arithmetic needs a range proof}}
}

int division(int a, int b) {
    return a / b;  // expected-warning {{integer arithmetic needs a range proof}}
}

int remainder(int a) {
    return a % -1;  // expected-warning {{integer arithmetic needs a range proof}}
}

int shift(int a, int b) {
    return a >> b;  // expected-warning {{integer arithmetic needs a range proof}}
}

i64 safe_product(i32 a, i32 b) {
    return (range_int(a) * range_int(b)).value();
}

i64 safe_native(i32 a, i32 b) {
    return i64{a} * i64{b};
}

int safe_constants() {
    return (10 - 2) * 3 + 2;
}

i32 safe_nested(u8 a, u8 b) {
    return (a + b) * 10 + 9;
}

u8 narrowed_safe(u8 a) {
    return (a & 127) * 2;
}

u8 narrowed_overflow(u8 a, u8 b) {
    // expected-warning@+1 {{integer arithmetic result may not fit the destination}}
    return static_cast<u8>(a + b);
}

u8 narrowed_underflow(u8 a, u8 b) {
    return a - b;  // expected-warning {{integer arithmetic result may not fit the destination}}
}

int negative_path_index(const int* data, u32 length) {
    if (length < 2 || length > 255) return 0;
    const auto last = range_int(length) - range_int<1, 2>{};
    // expected-warning@+1 {{use range_int::index() or at() for array indexing}}
    return data[last.value()];
}

int negative_index_through_alias(const int* data, range_int<-1, 5> index) {
    const auto at = index.value();
    // expected-warning@+1 {{use range_int::index() or at() for array indexing}}
    return data[static_cast<u32>(at)];
}

int negative_index_through_unmodified_local(const int* data, range_int<-1, 5> index) {
    auto at = index.value();
    // expected-warning@+1 {{use range_int::index() or at() for array indexing}}
    return data[at];
}

int range_value_still_requires_index(const int* data, range_int<0, 4> index) {
    // expected-warning@+1 {{use range_int::index() or at() for array indexing}}
    return data[index.value() & 3];
}

int proven_array_access(const int (&data)[4], range_int<0, 4> index) {
    return index.at(data);
}

int proven_path_index(const int* data, u32 length) {
    range_int<2, 256> validated;
    if (!decltype(validated)::try_from_i64(length, &validated)) return 0;
    const auto last = validated - range_int<1, 2>{};
    const auto at = last.index();
    return data[at];
}

template <typename T>
concept CanIndex = requires(T value) { value.index(); };

static_assert(CanIndex<range_int<0, 5>>);
static_assert(CanIndex<range_int<1, 255>>);
static_assert(!CanIndex<range_int<-1, 255>>);
static_assert(range_int<0, 5>::constant<3>().index() == 3);

struct Indices {
    int operator[](i64 index) const;
    int operator[](i64 row, i64 column) const;
};

int negative_overloaded_index(const Indices& values, range_int<-1, 5> index) {
    // expected-warning@+1 {{use range_int::index() or at() for array indexing}}
    return values[index.value()];
}

int explicit_overloaded_index(const Indices& values, range_int<0, 5> index) {
    // expected-warning@+1 {{use range_int::index() or at() for array indexing}}
    return values.operator[](index.value());
}

int multidimensional_index(const Indices& values, range_int<0, 5> row, range_int<0, 3> column) {
    // expected-warning@+1 {{use range_int::index() or at() for array indexing}}
    return values[row.index(), column.value()];
}

void bounded_loop(unsigned end) {
    for (unsigned i = 0; i < end; ++i) {
    }
}

void unbounded_loop(unsigned long long end) {
    // expected-warning@+1 {{integer arithmetic needs a range proof}}
    for (unsigned i = 0; i < end; ++i) {
    }
}

void changed_loop(unsigned end) {
    for (unsigned i = 0; i < end;
         ++i)  // expected-warning {{integer arithmetic needs a range proof}}
        i = ~0u;
}

template <typename T>
concept CanMultiply = requires(T a) { a * a; };

template <typename T>
concept CanNarrowToByte = requires(T value) { value.template to<u8>(); };

static_assert(CanNarrowToByte<range_int<0, 256>>);
static_assert(!CanNarrowToByte<range_int<-1, 256>>);
static_assert(!CanNarrowToByte<range_int<0, 257>>);
static_assert(CanMultiply<range_int<-100, 100>>);
static_assert(wrapping_add(UINT32_MAX, u32{1}) == 0);
static_assert(wrapping_sub(u64{0}, u64{1}) == UINT64_MAX);
static_assert(!CanMultiply<range_int<INT64_MIN>>);
static_assert((range_int<-3, 8>::constant<-3>() * range_int<-6, 3>::constant<-6>()).value() == 18);
static_assert(__is_same(decltype(range_int<-3, 8>{} * range_int<-6, 3>{}), range_int<-42, 19>));

static_assert([] {
    int out = 0;
    if (add_overflow(20, 22, &out) || out != 42) return false;
    if (!mul_overflow(1u << 31, 2, &out) || out != 0) return false;
    unsigned count = 0;
    return sub_overflow(0u, 1u, &count) && count == ~0u;
}());
