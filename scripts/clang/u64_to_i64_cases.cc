#include "rut/common/integer_conversion.h"

using namespace rut;

static_assert(static_cast<i64>(u64{INT64_MAX}) == INT64_MAX);
// expected-warning@+1 {{u64 to i64 conversion requires a range proof}}
static_assert(static_cast<i64>(u64{UINT64_MAX}) == -1);

i64 explicit_conversion(u64 value) {
    // expected-warning@+1 {{u64 to i64 conversion requires a range proof}}
    return static_cast<i64>(value);
}

i64 implicit_conversion(u64 value) {
    return value;  // expected-warning {{u64 to i64 conversion requires a range proof}}
}

template <typename T>
i64 generic_conversion(T value) {
    return value;  // expected-warning {{u64 to i64 conversion requires a range proof}}
}

i64 use_generic_conversion(u64 value) {
    return generic_conversion(value);
}

static_assert([] {
    i64 out = -1;
    return try_u64_to_i64(0, out) && out == 0 && try_u64_to_i64(u64{INT64_MAX}, out) &&
           out == INT64_MAX && !try_u64_to_i64(u64{INT64_MAX} + 1, out) && out == INT64_MAX &&
           !try_u64_to_i64(UINT64_MAX, out) && out == INT64_MAX;
}());
