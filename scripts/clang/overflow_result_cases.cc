// Exercised with Clang -verify by the integer safety audit.
#include "rut/common/checked_arithmetic.h"

using namespace rut;

[[nodiscard]] bool checked_sum(int a, int b, int* out) {
    if (add_overflow(a, b, out)) return false;
    return true;
}

[[nodiscard]] bool checked_difference(int a, int b, int* out) {
    return !sub_overflow(a, b, out) && *out >= 0;
}

bool missing_annotation(int a, int b, int* out) {
    // expected-warning@+1 {{checked arithmetic requires an explicit return}}
    if (add_overflow(a, b, out)) return false;
    return true;
}

[[nodiscard]] bool ignored_check(int a, int b, int* out) {
    // expected-warning@+1 {{checked arithmetic requires an explicit return}}
    (void)sub_overflow(a, b, out);
    return true;
}

[[nodiscard]] bool fake_success(int a, int b, int* out) {
    // expected-warning@+1 {{checked arithmetic requires an explicit return}}
    if (mul_overflow(a, b, out)) return true;
    return *out >= 0;
}

[[nodiscard]] bool ineffective_guard(int a, int b, int* out, bool enabled) {
    // expected-warning@+1 {{checked arithmetic requires an explicit return}}
    if (mul_overflow(a, b, out) && enabled) return false;
    return true;
}

[[nodiscard]] bool possible_success(int a, int b, int* out, bool enabled) {
    // expected-warning@+1 {{checked arithmetic requires an explicit return}}
    if (mul_overflow(a, b, out)) {
        if (enabled) return true;
        return false;
    }
    return true;
}
