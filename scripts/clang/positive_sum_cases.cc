#include "rut/common/bounded_int.h"
#include "rut/runtime/http2_conn.h"

void consume(long value RUT_POSITIVE);
void accepts_zero(long value);

void unchecked(long a, long b) {
    long sum = a + b;
    consume(sum);  // expected-warning {{Signed addition may overflow}}
}
void checked_too_late(long a, long b) {
    long sum = a + b;
    if (sum > 0) consume(sum);  // expected-warning {{Signed addition may overflow}}
}
void compound(long a, long b) {
    a += b;
    if (a > 0) consume(a);  // expected-warning {{Signed addition may overflow}}
}
void ignores_overflow(long a, long b) {
    long sum;
    (void)__builtin_add_overflow(a, b, &sum);
    if (sum > 0) consume(sum);  // expected-warning {{Signed addition may overflow}}
}
void zero_is_insufficient(long a, long b) {
    long sum;
    if (!__builtin_add_overflow(a, b, &sum) && sum >= 0)
        consume(sum);  // expected-warning {{Result must be proven strictly positive}}
}
void checked(long a, long b) {
    long sum;
    if (__builtin_add_overflow(a, b, &sum) || sum <= 0) return;
    consume(sum);
}
void bounded(int a, int b) {
    if (a > 0 && a < 100 && b > 0 && b < 100) consume(a + b);
}
void widened(int a, int b) {
    long sum = static_cast<long>(a) + b;
    if (sum > 0) consume(sum);
    accepts_zero(sum);
}

void guarded_before_add(long a, long b) {
    if (a <= 0 || b <= 0 || a > __LONG_MAX__ - b) return;
    consume(a + b);
}
void bounded_compound(int a, int b) {
    if (a <= 0 || a > 10 || b <= 0 || b > 10) return;
    a += b;
    consume(a);
}
void wrong_branch(long a, long b, bool skip) {
    long sum;
    if (__builtin_add_overflow(a, b, &sum)) return;
    if (skip && sum <= 0) return;
    consume(sum);  // expected-warning {{Result must be proven strictly positive}}
}

void credit(rut::Http2Conn& w, long n) {
    w.conn_send_window += n;  // expected-warning {{Signed addition may overflow}}
}
void saved_credit(rut::Http2Conn& w, int a, int b) {
    long sum = static_cast<long>(a) + b;
    w.conn_send_window = sum;  // expected-warning {{Result must be proven strictly positive}}
}
void drain(rut::Http2Conn& w) {
    w.conn_send_window = 0;
}

void empty_credit(rut::Http2Conn& w) {
    w.conn_send_window = 1 + -1;  // expected-warning {{Result must be proven strictly positive}}
}

static long add_unchecked(long a, long b) {
    return a + b;
}
void returned_sum(long a, long b) {
    long sum = add_unchecked(a, b);
    if (sum > 0) consume(sum);  // expected-warning {{Signed addition may overflow}}
}

void narrow(int a, int b) {
    long sum = static_cast<long>(a) + b;
    int small = static_cast<int>(sum);
    if (small > 0) consume(small);  // expected-warning {{Sum may be out of range}}
}
void checked_narrow(int a, int b) {
    long sum = static_cast<long>(a) + b;
    if (sum <= 0 || sum > __INT_MAX__) return;
    consume(static_cast<int>(sum));
}

void known_overflow() {
    long a = __LONG_MAX__;
    long b = 1;
    consume(a + b);  // expected-warning {{Signed addition exceeds its representable range}}
}

int below_signed_minimum() {
    int a = INT32_MIN;
    int b = -1;
    return a + b;  // expected-warning {{Signed addition exceeds its representable range}}
}

int exactly_signed_minimum() {
    int a = INT32_MIN + 1;
    int b = -1;
    return a + b;
}

void discarded_status(long a, long b) {
    rut::i64 sum;
    rut::checked_positive_sum(a, b, INT64_MAX, sum);  // discard-error {{ignoring return value}}
}

static_assert([] {
    rut::i64 value = 7;
    return !rut::checked_positive_sum(INT64_MAX, 1, INT64_MAX, value) && value == 7 &&
           !rut::checked_positive_sum(INT64_MIN, -1, INT64_MAX, value) && value == 7 &&
           !rut::checked_positive_sum(1, -1, 7, value) && value == 7 &&
           !rut::checked_positive_sum(7, 1, 7, value) && value == 7 &&
           rut::checked_positive_sum(value, 1, 8, value) && value == 8;
}());

using Count = rut::BoundedInt<struct CountTag, 0, INT64_MAX>;
using Offset = rut::BoundedInt<struct OffsetTag, 0, INT64_MAX>;

template <typename T, typename U>
concept CanAdd = requires(T a, U b) { a + b; };
static_assert(!CanAdd<Count, Count> && !CanAdd<Count, Offset> && !CanAdd<Count, int>);
static_assert(!__is_constructible(Count, long) && !__is_constructible(Count, Offset));
static_assert(sizeof(Count) == sizeof(rut::i64) && alignof(Count) == alignof(rut::i64));
static_assert([] {
    auto zero = Count::constant<0>();
    auto max = Count::constant<INT64_MAX>();
    return !zero.try_decrement() && zero.value() == 0 && zero.try_increment() &&
           zero.value() == 1 && !max.try_increment() && max.value() == INT64_MAX &&
           max.try_decrement() && max.value() == INT64_MAX - 1;
}());

template <typename T>
concept RawIncrement = requires(T v) { ++v; };
template <typename T>
concept RawDecrement = requires(T v) { --v; };
static_assert(!RawIncrement<Count> && !RawDecrement<Count>);

void unchecked_factory_input(long a, long b) {
    (void)Count::from(a + b);  // expected-warning {{Signed addition may overflow}}
}
