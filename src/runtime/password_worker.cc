#include "rut/runtime/password_worker.h"

#include "core/expected.h"
#include "rut/common/types.h"
#include "rut/runtime/error.h"
#include "rut/runtime/password.h"

#include <errno.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <time.h>

namespace rut {
PasswordWorker::~PasswordWorker() {
    stop();
}

core::Expected<void, Error> PasswordWorker::start() {
    if (started) return core::make_unexpected(Error::make(EALREADY, Error::Source::Thread));
    __atomic_store_n(&stopping, 0u, __ATOMIC_RELEASE);
    const i32 kRc = pthread_create(&worker_thread, nullptr, entry, this);
    if (kRc != 0) return core::make_unexpected(Error::make(kRc, Error::Source::Thread));
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
    for (auto& slot : slots) {
        wipe(slot);
        __atomic_store_n(&slot.state, static_cast<u32>(Empty), __ATOMIC_RELEASE);
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
            worked = true;
        }
        if (!worked) nanosleep(&kIdle, nullptr);
    }
}
}  // namespace rut
