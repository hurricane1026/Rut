#include "rut/runtime/io_event.h"

namespace rut {
namespace {

[[nodiscard]] consteval bool timer_result_domain_matches() {
    // Include the four documented outcomes, foreign errors, and a positive
    // byte count. The selector is the cancel bit, independent of the owner id.
    constexpr i32 results[] = {-ETIME, -ECANCELED, 0, -ENOENT, -EALREADY, -EIO, 1};
    constexpr u32 generations[] = {0, 1, kResponseReadTimerGenerationMask};
    constexpr u32 markers[] = {0, kResponseReadTimerCancelBit};
    for (u32 generation : generations) {
        for (u32 marker : markers) {
            for (i32 result : results) {
                IoEvent event{};
                event.type = IoEventType::ResponseReadTimer;
                event.non_upstream_generation = generation | marker;
                event.result = result;
                const bool target = result == -ETIME || result == -ECANCELED;
                const bool cancel = result == 0 || result == -ENOENT;
                if (valid_response_read_timer_transport_event(event) !=
                    (generation != 0 && (marker ? cancel : target)))
                    return false;
            }
        }
    }
    return true;
}

[[nodiscard]] consteval bool timer_payload_is_isolated(u32 tagged_generation,
                                                       i32 completion_result) {
    IoEvent event{};
    // Decomposing the production aggregate makes a new payload member a build
    // error until its meaning for a response timer has been considered.
    auto& [conn_id,
           result,
           buf_id,
           has_buf,
           type,
           more,
           aux,
           episode,
           generation,
           witness,
           deadline_generation,
           profile,
           method,
           begin,
           end,
           ring_empty] = event;
    conn_id = kIoUserDataMaxConnId;
    result = completion_result;
    generation = tagged_generation;
    for (unsigned tag = 0; tag <= 255; ++tag) {
        type = static_cast<IoEventType>(tag);
        if (valid_response_read_timer_transport_event(event) !=
            (type == IoEventType::ResponseReadTimer))
            return false;
    }
    type = IoEventType::ResponseReadTimer;
    auto rejects_field = [&](auto& field, auto value) {
        const auto original = field;
        field = value;
        const bool rejected = !valid_response_read_timer_transport_event(event);
        field = original;
        return rejected;
    };
    return rejects_field(buf_id, 1) && rejects_field(has_buf, 1) && rejects_field(more, 1) &&
           rejects_field(aux, 1) && rejects_field(episode, 1) &&
           rejects_field(witness, IoEventCopyWitness::Full) &&
           rejects_field(witness, IoEventCopyWitness::Invalid) &&
           rejects_field(deadline_generation, 1) && rejects_field(profile, 1) &&
           rejects_field(method, 0) && rejects_field(begin, 1) && rejects_field(end, 1) &&
           rejects_field(ring_empty, 1);
}

static_assert(timer_result_domain_matches(), "Response timer result domain mismatch");
static_assert(timer_payload_is_isolated(1, -ETIME) && timer_payload_is_isolated(1, -ECANCELED) &&
                  timer_payload_is_isolated(1 | kResponseReadTimerCancelBit, 0) &&
                  timer_payload_is_isolated(1 | kResponseReadTimerCancelBit, -ENOENT),
              "Response timer accepts unrelated event metadata");

}  // namespace
}  // namespace rut
