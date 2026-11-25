#include "rut/common/integer_range.h"

using namespace rut;

struct Response {
    u32 resp_body_sent;

    void original(u32 bytes) {
        // expected-error@+2 {{overflow branch replaces the checked result}}
        if (__builtin_add_overflow(resp_body_sent, bytes, &resp_body_sent))
            resp_body_sent = UINT32_MAX;
    }

    void conditional(u32 bytes) {
        u32 next;
        // expected-error@+1 {{overflow branch replaces the checked result}}
        resp_body_sent = __builtin_add_overflow(resp_body_sent, bytes, &next) ? UINT32_MAX : next;
    }

    void through_flag(u32 bytes) {
        u32 next;
        const bool overflow = __builtin_add_overflow(resp_body_sent, bytes, &next);
        if (!overflow)
            resp_body_sent = next;
        else {
            // expected-error@+1 {{overflow branch replaces the checked result}}
            resp_body_sent = UINT32_MAX;
        }
    }

    [[nodiscard]] bool checked(u32 bytes) {
        u32 next;
        if (__builtin_add_overflow(resp_body_sent, bytes, &next)) return false;
        resp_body_sent = next;
        return true;
    }
};

void reset_if_underflow(u32& remaining, u32 length) {
    if (__builtin_sub_overflow(remaining, length, &remaining)) {
        remaining = 0;  // expected-error {{overflow branch replaces the checked result}}
    }
}

bool report_failure(u32& capacity, u32 scale, bool& failed) {
    u32 next;
    if (__builtin_mul_overflow(capacity, scale, &next)) {
        failed = true;
        return false;
    }
    capacity = next;
    return true;
}

static_assert(saturating_add(UINT64_MAX, 1) == UINT64_MAX);

struct ExactCounter {
    u32 value RUT_EXACT_COUNTER;

    bool publish_before_check(u32 bytes) {
        // expected-error@+1 {{check overflow before storing a result in an exact counter}}
        return !__builtin_add_overflow(value, bytes, &value);
    }

    void publish_fallback(u32 bytes) {
        // expected-error@+1 {{exact counter cannot use a saturating result}}
        value = static_cast<u32>(saturating_add(value, bytes));
    }

    [[nodiscard]] bool publish_after_check(u32 bytes) {
        u32 next;
        if (__builtin_add_overflow(value, bytes, &next)) return false;
        value = next;
        return true;
    }
};
