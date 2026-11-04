#include "rut/runtime/password_worker.h"

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/error.h"
#include "rut/runtime/password.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

namespace rut {
PasswordWorker::~PasswordWorker() {
    stop();
}

core::Expected<void, Error> PasswordWorker::start() {
    if (started) return core::make_unexpected(Error::make(EALREADY, Error::Source::Thread));
    i32 fds[2] = {-1, -1};
#ifdef __linux__
    if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0)
        return core::make_unexpected(Error::from_errno(Error::Source::Pipe));
#else
    if (pipe(fds) != 0) return core::make_unexpected(Error::from_errno(Error::Source::Pipe));
    for (i32 fd : fds) {
        if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
            const auto kError = Error::from_errno(Error::Source::Pipe);
            close(fds[0]);
            close(fds[1]);
            return core::make_unexpected(kError);
        }
    }
#endif
    notification_read = fds[0];
    notification_write = fds[1];
    __atomic_store_n(&stopping, 0u, __ATOMIC_RELEASE);
    const i32 kRc = pthread_create(&worker_thread, nullptr, entry, this);
    if (kRc != 0) {
        close_notifications();
        return core::make_unexpected(Error::make(kRc, Error::Source::Thread));
    }
    started = true;
    return {};
}

void PasswordWorker::wipe(Slot& slot) {
    OPENSSL_cleanse(slot.password, sizeof(slot.password));
    OPENSSL_cleanse(slot.record, sizeof(slot.record));
    slot.password_len = 0;
    slot.matched = false;
}

void PasswordWorker::stop() {
    if (!started) return;
    __atomic_store_n(&stopping, 1u, __ATOMIC_RELEASE);
    // A join failure violates exclusive lifecycle ownership. Never release
    // storage while a worker might still be using it.
    if (pthread_join(worker_thread, nullptr) != 0) __builtin_trap();
    started = false;
    close_notifications();
    for (auto& slot : slots) {
        wipe(slot);
        __atomic_store_n(&slot.state, static_cast<u32>(Empty), __ATOMIC_RELEASE);
    }
}

void PasswordWorker::close_notifications() {
    if (notification_read >= 0) close(notification_read);
    if (notification_write >= 0) close(notification_write);
    notification_read = -1;
    notification_write = -1;
}

void PasswordWorker::notify_completion() {
    const u8 kByte = 1;
    for (;;) {
        const auto kWritten = write(notification_write, &kByte, 1);
        if (kWritten == 1) return;
        if (kWritten < 0 && errno == EINTR) continue;
        // A full pipe already carries a readable wakeup. Other errors violate
        // ownership: the producer must never close/change this borrowed fd.
        if (kWritten < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        __builtin_trap();
    }
}

bool PasswordWorker::drain_completions() {
    if (!started) return false;
    u8 bytes[256];
    for (;;) {
        const auto kCount = read(notification_read, bytes, sizeof(bytes));
        if (kCount > 0) continue;
        if (kCount < 0 && errno == EINTR) continue;
        return kCount < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
    }
}

PasswordTask PasswordWorker::submit(Str password, Str record) {
    if (!started || next_generation == 0 || !password.ptr || password.len == 0 ||
        password.len > kPasswordMaxBytes || !record.ptr || record.len != kPasswordRecordBytes)
        return {};
    for (u32 i = 0; i < kCapacity; ++i) {
        auto& slot = slots[i];
        if (__atomic_load_n(&slot.state, __ATOMIC_ACQUIRE) != Empty) continue;
        // Only this producer publishes Empty slots; the worker cannot touch them.
        for (u32 j = 0; j < password.len; ++j) slot.password[j] = password.ptr[j];
        for (u32 j = 0; j < record.len; ++j) slot.record[j] = record.ptr[j];
        slot.password_len = password.len;
        slot.generation = next_generation++;
        __atomic_store_n(&slot.state, static_cast<u32>(Queued), __ATOMIC_RELEASE);
        return {this, slot.generation, i};
    }
    return {};
}

PasswordWorker::Slot* PasswordWorker::lookup(PasswordTask task) {
    if (!started || task.owner != this || task.slot >= kCapacity || task.generation == 0)
        return nullptr;
    auto& slot = slots[task.slot];
    return slot.generation == task.generation ? &slot : nullptr;
}

PasswordTaskStatus PasswordWorker::poll(PasswordTask task) {
    auto* slot = lookup(task);
    if (!slot) return PasswordTaskStatus::Invalid;
    switch (__atomic_load_n(&slot->state, __ATOMIC_ACQUIRE)) {
        case Queued:
            return PasswordTaskStatus::Queued;
        case Running:
            return PasswordTaskStatus::Running;
        case Done: {
            const auto kStatus =
                slot->matched ? PasswordTaskStatus::Matched : PasswordTaskStatus::Rejected;
            slot->matched = false;
            __atomic_store_n(&slot->state, static_cast<u32>(Empty), __ATOMIC_RELEASE);
            return kStatus;
        }
        default:
            return PasswordTaskStatus::Invalid;
    }
}

bool PasswordWorker::cancel(PasswordTask task) {
    auto* slot = lookup(task);
    if (!slot) return false;
    u32 state = __atomic_load_n(&slot->state, __ATOMIC_ACQUIRE);
    for (;;) {
        u32 next = 0;
        if (state == Queued)
            next = CancelQueued;
        else if (state == Running)
            next = CancelRunning;
        else if (state == Done) {
            // Done is stable until the single producer consumes it.
            slot->matched = false;
            __atomic_store_n(&slot->state, static_cast<u32>(Empty), __ATOMIC_RELEASE);
            return true;
        } else
            return false;
        if (__atomic_compare_exchange_n(
                &slot->state, &state, next, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return true;
    }
}

void* PasswordWorker::entry(void* self) {
    static_cast<PasswordWorker*>(self)->run();
    return nullptr;
}

void PasswordWorker::run() {
    const timespec kIdle = {0, 1000000};
    while (!__atomic_load_n(&stopping, __ATOMIC_ACQUIRE)) {
        bool worked = false;
        for (auto& slot : slots) {
            if (__atomic_load_n(&stopping, __ATOMIC_ACQUIRE)) break;
            u32 state = __atomic_load_n(&slot.state, __ATOMIC_ACQUIRE);
            if (state == CancelQueued) {
                wipe(slot);
                __atomic_store_n(&slot.state, static_cast<u32>(Empty), __ATOMIC_RELEASE);
                notify_completion();
                worked = true;
                continue;
            }
            state = Queued;
            if (!__atomic_compare_exchange_n(&slot.state,
                                             &state,
                                             static_cast<u32>(Running),
                                             false,
                                             __ATOMIC_ACQ_REL,
                                             __ATOMIC_ACQUIRE))
                continue;
            const bool kMatched = password_verify({slot.password, slot.password_len},
                                                  {slot.record, kPasswordRecordBytes});
            wipe(slot);
            slot.matched = kMatched;
            state = Running;
            if (!__atomic_compare_exchange_n(&slot.state,
                                             &state,
                                             static_cast<u32>(Done),
                                             false,
                                             __ATOMIC_RELEASE,
                                             __ATOMIC_RELAXED)) {
                slot.matched = false;
                __atomic_store_n(&slot.state, static_cast<u32>(Empty), __ATOMIC_RELEASE);
            }
            notify_completion();
            worked = true;
        }
        if (!worked) nanosleep(&kIdle, nullptr);
    }
}
}  // namespace rut
