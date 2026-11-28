#pragma once

#include "rut/common/types.h"
#include <atomic>

namespace rut {

enum class ShardWorkPriority : u8 { Low, Normal, High };
enum class ShardDeadlinePolicy : u8 { Soft, Hard };

struct ShardWorkSchedule {
    u64 deadline_ns = 0;  // Zero means no deadline.
    ShardWorkPriority priority = ShardWorkPriority::Normal;

    bool expires_before_start(u64 now, ShardDeadlinePolicy policy) const {
        return policy == ShardDeadlinePolicy::Hard && deadline_ns != 0 && now >= deadline_ns;
    }
};

// Fixed-capacity, single producer and single consumer. A spare slot
// distinguishes a full ring from an empty ring after cursor wraparound.
template <typename Message, i32 Capacity>
class ShardSpscRing {
    static_assert(Capacity > 0 && Capacity < INT32_MAX);
    static constexpr i32 kSlots = Capacity + 1;

    struct alignas(64) Cursor {
        std::atomic<i32> published{0};
        i32 local = 0;
        i32 cached_peer = 0;
    };

    Cursor producer_;
    Cursor consumer_;
    Message slots_[kSlots]{};

    static i32 next(i32 cursor) { return cursor + 1 == kSlots ? 0 : cursor + 1; }

public:
    bool stage(const Message& message) {
        const i32 after = next(producer_.local);
        if (after == producer_.cached_peer) {
            producer_.cached_peer = consumer_.published.load(std::memory_order_acquire);
            if (after == producer_.cached_peer) return false;
        }
        slots_[producer_.local] = message;
        producer_.local = after;
        return true;
    }

    bool publish() {
        if (producer_.local == producer_.published.load(std::memory_order_relaxed)) return false;
        producer_.published.store(producer_.local, std::memory_order_release);
        return true;
    }

    bool has_incoming() const {
        return consumer_.local != producer_.published.load(std::memory_order_acquire);
    }

    // The receiver copies out before giving this batch's slots back.
    i32 drain(Message* out, i32 limit) {
        consumer_.cached_peer = producer_.published.load(std::memory_order_acquire);
        i32 count = 0;
        while (count < limit && consumer_.local != consumer_.cached_peer) {
            out[count] = slots_[consumer_.local];
            ++count;
            consumer_.local = next(consumer_.local);
        }
        if (count != 0) consumer_.published.store(consumer_.local, std::memory_order_release);
        return count;
    }
};

class alignas(64) ShardWakeChannel {
    std::atomic<bool> armed_{false};

public:
    void* context = nullptr;
    void (*signal)(void*) = nullptr;

    void notify_published() {
        // Paired with the receiver's fence to rule out both sides observing
        // the old value in the publish-versus-sleep race.
        std::atomic_thread_fence(std::memory_order_seq_cst);
        bool expected = true;
        if (armed_.load(std::memory_order_relaxed) &&
            armed_.compare_exchange_strong(expected, false, std::memory_order_relaxed))
            signal(context);
    }

    template <typename HasIncoming>
    bool prepare_wait(HasIncoming has_incoming) {
        if (has_incoming()) return false;
        armed_.store(true, std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_seq_cst);
        if (!has_incoming()) return true;
        finish_wait();
        return false;
    }

    void finish_wait() { armed_.store(false, std::memory_order_relaxed); }
};

template <typename Message, i32 Capacity>
class ShardReadyHeap {
    struct Item {
        Message message;
        i64 order;
    };
    Item items_[Capacity]{};
    i32 size_ = 0;
    i64 next_order_ = 0;

    static bool before(const Item& a, const Item& b) {
        const auto& x = a.message.schedule;
        const auto& y = b.message.schedule;
        if (x.deadline_ns != y.deadline_ns)
            return y.deadline_ns == 0 || (x.deadline_ns != 0 && x.deadline_ns < y.deadline_ns);
        if (x.priority != y.priority) return x.priority > y.priority;
        return a.order < b.order;
    }

public:
    bool empty() const { return size_ == 0; }
    i32 available() const { return Capacity - size_; }

    bool push(const Message& message) {
        if (size_ == Capacity || next_order_ == INT64_MAX) return false;
        Item incoming{message, next_order_++};
        i32 index = size_++;
        while (index > 0) {
            const i32 parent = (index - 1) / 2;
            if (!before(incoming, items_[parent])) break;
            items_[index] = items_[parent];
            index = parent;
        }
        items_[index] = incoming;
        return true;
    }

    bool pop(Message& message) {
        if (empty()) return false;
        message = items_[0].message;
        const Item last = items_[--size_];
        if (empty()) {
            next_order_ = 0;
            return true;
        }
        i32 index = 0;
        while (index < size_ / 2) {
            i32 child = index * 2 + 1;
            if (child + 1 < size_ && before(items_[child + 1], items_[child])) ++child;
            if (!before(items_[child], last)) break;
            items_[index] = items_[child];
            index = child;
        }
        items_[index] = last;
        return true;
    }
};

}  // namespace rut
