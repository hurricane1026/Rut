#pragma once

#include "rut/common/types.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

namespace rut {

// Single-shard pipe storage for an explicitly admitted plaintext body. This
// owner does not authorize publication: callers still supply the declared-body
// receive bound and the Bounded-eligible send length, and validate connection,
// episode and deadline identity before applying a completion.
//
// Reservations distinguish SQ rollback from submitted kernel ownership. The
// storage must not be returned to its allocator while either side is
// reserved/submitted. Construct the owner in fresh allocator storage before use.
struct ResponseBodyPipe {
    ResponseBodyPipe() = default;
    ResponseBodyPipe(const ResponseBodyPipe&) = delete;
    ResponseBodyPipe& operator=(const ResponseBodyPipe&) = delete;

    enum class Phase : u8 { Idle, Reserved, Submitted };
    struct Operation {
        u32 serial = 0;
        u32 limit = 0;
        Phase phase = Phase::Idle;
    };

    i32 read_fd = -1;
    i32 write_fd = -1;
    u32 capacity = 0;
    u32 bytes = 0;
    // Never reset on close/reopen. An exhausted owner cannot arm another op.
    u32 sequence = 0;
    Operation input{};
    Operation output{};

    bool busy() const { return input.phase != Phase::Idle || output.phase != Phase::Idle; }
    bool active() const { return read_fd >= 0 && write_fd >= 0 && capacity != 0; }

    [[nodiscard]] bool open(u32 requested_capacity) {
        if (read_fd >= 0 || write_fd >= 0 || busy() || bytes != 0 || requested_capacity == 0 ||
            requested_capacity > static_cast<u32>(INT32_MAX))
            return false;
#ifdef __linux__
        i32 fds[2];
        if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0) return false;
        // Per-user limits may deny growth. The actual smaller capacity is
        // usable; no global limit is changed. Byte credit is conservative:
        // fragmented pipe buffers may exhaust page slots before this bound.
        (void)fcntl(fds[0], F_SETPIPE_SZ, static_cast<i32>(requested_capacity));
        const i32 actual = fcntl(fds[0], F_GETPIPE_SZ);
        if (actual <= 0) {
            ::close(fds[0]);
            ::close(fds[1]);
            return false;
        }
        read_fd = fds[0];
        write_fd = fds[1];
        capacity = static_cast<u32>(actual);
        // Even if the kernel rounds capacity up, keep the requested byte cap.
        if (capacity > requested_capacity) capacity = requested_capacity;
        return true;
#else
        return false;
#endif
    }

    // Close also discards unconsumed bytes, for abort/teardown. Submitted ops
    // must first retire through their terminal CQEs, including cancellation.
    [[nodiscard]] bool close() {
        if (busy()) return false;
        if (read_fd >= 0) ::close(read_fd);
        if (write_fd >= 0) ::close(write_fd);
        read_fd = write_fd = -1;
        capacity = bytes = 0;
        return true;
    }

    [[nodiscard]] bool reserve_input(u32 declared_remaining, Operation* out) {
        if (!active() || bytes > capacity) return false;
        const u32 space = capacity - bytes;
        return reserve(input, declared_remaining < space ? declared_remaining : space, out);
    }
    [[nodiscard]] bool reserve_output(u32 publication_credit, Operation* out) {
        if (!active()) return false;
        return reserve(output, publication_credit < bytes ? publication_credit : bytes, out);
    }
    [[nodiscard]] bool submit_input(u32 serial) { return submit(input, serial); }
    [[nodiscard]] bool submit_output(u32 serial) { return submit(output, serial); }
    [[nodiscard]] bool rollback_input(u32 serial) { return rollback(input, serial); }
    [[nodiscard]] bool rollback_output(u32 serial) { return rollback(output, serial); }

    [[nodiscard]] bool complete_input(u32 serial, i32 result) {
        if (!matches(input, serial, result)) return false;
        if (result > 0) {
            const u32 n = static_cast<u32>(result);
            if (bytes > capacity || n > capacity - bytes) return false;
            bytes += n;
        }
        input = {};
        return true;
    }
    [[nodiscard]] bool complete_output(u32 serial, i32 result) {
        if (!matches(output, serial, result)) return false;
        if (result > 0) {
            const u32 n = static_cast<u32>(result);
            if (n > bytes) return false;
            bytes -= n;
        }
        output = {};
        return true;
    }

    // Copy fallback for fragmented/page-slot-full pipes. The caller reserves
    // ordinary body storage first, commits exactly this result, and does not
    // count migration as fresh origin progress. No async user may overlap.
    i32 drain_into(u8* destination, u32 size) {
        if (!active() || !destination || size == 0) return -EINVAL;
        if (busy()) return -EBUSY;
        const u32 length = size < bytes ? size : bytes;
        if (length == 0) return 0;
        const ssize_t result = ::read(read_fd, destination, length);
        if (result < 0) return -errno;
        bytes -= static_cast<u32>(result);
        return static_cast<i32>(result);
    }

private:
    bool reserve(Operation& operation, u32 limit, Operation* out) {
        if (!out || operation.phase != Phase::Idle || limit == 0 || sequence == UINT32_MAX)
            return false;
        operation = {++sequence, limit, Phase::Reserved};
        *out = operation;
        return true;
    }
    static bool submit(Operation& operation, u32 serial) {
        if (operation.phase != Phase::Reserved || serial == 0 || operation.serial != serial)
            return false;
        operation.phase = Phase::Submitted;
        return true;
    }
    static bool rollback(Operation& operation, u32 serial) {
        if (operation.phase != Phase::Reserved || serial == 0 || operation.serial != serial)
            return false;
        operation = {};
        return true;
    }
    static bool matches(const Operation& operation, u32 serial, i32 result) {
        return operation.phase == Phase::Submitted && serial != 0 && operation.serial == serial &&
               (result <= 0 || static_cast<u32>(result) <= operation.limit);
    }
};

}  // namespace rut
