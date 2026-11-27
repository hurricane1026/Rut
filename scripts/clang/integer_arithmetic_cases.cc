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
