#include "rut/runtime/access_log_live_producer.h"

#include <errno.h>

namespace rut {

bool SourceLiveAccessLogProducer::init(LiveAccessLogRing* ring,
                                       SourceLiveAccessLogSession* session,
                                       u32 ring_index,
                                       SourceLiveAccessLogLeaseSlot* lease) {
    if (initialized()) {
        session_->report_producer_fatal(
            SourceLiveAccessLogFatalKind::Protocol, ring_index_, EALREADY);
        return false;
    }
    if (session == nullptr) return false;
    if (!session->producer_binding_valid(ring, ring_index, lease)) {
        session->report_producer_fatal(SourceLiveAccessLogFatalKind::Protocol, ring_index, EINVAL);
        return false;
    }
    ring_ = ring;
    session_ = session;
    lease_ = lease;
    host_ring_ = nullptr;
    ring_index_ = ring_index;
    return true;
}

bool SourceLiveAccessLogProducer::init_host(LiveAccessLogRing* ring,
                                            SourceLiveAccessLogHostRing* host_ring,
                                            SourceLiveAccessLogSession* session,
                                            u32 ring_index,
                                            SourceLiveAccessLogLeaseSlot* lease) {
    if (initialized()) {
        session_->report_producer_fatal(
            SourceLiveAccessLogFatalKind::Protocol, ring_index_, EALREADY);
        return false;
    }
    if (session == nullptr) return false;
    if (!session->producer_host_binding_valid(ring, host_ring, ring_index, lease)) {
        session->report_producer_fatal(SourceLiveAccessLogFatalKind::Protocol, ring_index, EINVAL);
        return false;
    }
    ring_ = ring;
    host_ring_ = host_ring;
    session_ = session;
    lease_ = lease;
    ring_index_ = ring_index;
    return true;
}

void SourceLiveAccessLogProducer::reset() {
    ring_ = nullptr;
    session_ = nullptr;
    lease_ = nullptr;
    host_ring_ = nullptr;
    ring_index_ = 0u;
}

SourceLiveAccessLogPublishResult SourceLiveAccessLogProducer::publish(const AccessLogEntry& entry) {
    if (!initialized()) return {};
    if (!session_->producer_binding_valid(ring_, ring_index_, lease_)) {
        session_->report_producer_fatal(
            SourceLiveAccessLogFatalKind::Protocol, ring_index_, EPROTO);
        return {SourceLiveAccessLogPublishStatus::InvalidConfiguration, {}};
    }
    if (session_->fatal().kind != SourceLiveAccessLogFatalKind::None)
        return {SourceLiveAccessLogPublishStatus::Fatal, {}};

    const LiveAccessLogPublishResult published = ring_->try_publish(entry);
    if (published.status == LiveAccessLogPublishStatus::Full) {
        session_->report_producer_fatal(
            SourceLiveAccessLogFatalKind::RingFull, ring_index_, ENOBUFS);
        return {SourceLiveAccessLogPublishStatus::Fatal, {}};
    }
    if (published.status != LiveAccessLogPublishStatus::Published) {
        session_->report_producer_fatal(
            SourceLiveAccessLogFatalKind::Protocol, ring_index_, EPROTO);
        return {SourceLiveAccessLogPublishStatus::Fatal, {}};
    }

    const SourceLiveAccessLogNotifyStatus notified = session_->notify(ring_index_);
    if (notified == SourceLiveAccessLogNotifyStatus::Notified ||
        notified == SourceLiveAccessLogNotifyStatus::Coalesced)
        return {SourceLiveAccessLogPublishStatus::Published, published.ticket};
    if (notified == SourceLiveAccessLogNotifyStatus::InvalidLifecycle ||
        notified == SourceLiveAccessLogNotifyStatus::InvalidRingIndex)
        session_->report_producer_fatal(
            SourceLiveAccessLogFatalKind::Protocol, ring_index_, EPROTO);
    return {SourceLiveAccessLogPublishStatus::Fatal, published.ticket};
}

SourceLiveAccessLogPublishResult SourceLiveAccessLogProducer::publish_host(
    const AccessLogEntry& entry, const AccessLogDownstreamHostRecord& host) {
    if (!initialized() || host_ring_ == nullptr) return {};
    if (!session_->producer_host_binding_valid(ring_, host_ring_, ring_index_, lease_)) {
        session_->report_producer_fatal(
            SourceLiveAccessLogFatalKind::Protocol, ring_index_, EPROTO);
        return {SourceLiveAccessLogPublishStatus::InvalidConfiguration, {}};
    }
    if (session_->fatal().kind != SourceLiveAccessLogFatalKind::None)
        return {SourceLiveAccessLogPublishStatus::Fatal, {}};
    if (!access_log_downstream_host_record_is_canonical(host)) {
        session_->report_producer_fatal(
            SourceLiveAccessLogFatalKind::Protocol, ring_index_, EPROTO);
        return {SourceLiveAccessLogPublishStatus::Fatal, {}};
    }

    const u64 position = ring_->published_pos.load(std::memory_order_relaxed);
    const u64 committed = ring_->committed_pos.load(std::memory_order_acquire);
    const u64 pending = position - committed;
    if (pending > LiveAccessLogRing::kCapacity) {
        session_->report_producer_fatal(
            SourceLiveAccessLogFatalKind::Protocol, ring_index_, EPROTO);
        return {SourceLiveAccessLogPublishStatus::Fatal, {}};
    }
    if (pending == LiveAccessLogRing::kCapacity) {
        session_->report_producer_fatal(
            SourceLiveAccessLogFatalKind::RingFull, ring_index_, ENOBUFS);
        return {SourceLiveAccessLogPublishStatus::Fatal, {}};
    }

    SourceLiveAccessLogHostSlot& slot =
        host_ring_->slots[position & SourceLiveAccessLogHostRing::kMask];
    slot.record = host;
    slot.start_position = position;
    const LiveAccessLogPublishResult published = ring_->try_publish(entry);
    if (published.status != LiveAccessLogPublishStatus::Published) {
        session_->report_producer_fatal(
            SourceLiveAccessLogFatalKind::Protocol, ring_index_, EPROTO);
        return {SourceLiveAccessLogPublishStatus::Fatal, {}};
    }

    const SourceLiveAccessLogNotifyStatus notified = session_->notify(ring_index_);
    if (notified == SourceLiveAccessLogNotifyStatus::Notified ||
        notified == SourceLiveAccessLogNotifyStatus::Coalesced)
        return {SourceLiveAccessLogPublishStatus::Published, published.ticket};
    if (notified == SourceLiveAccessLogNotifyStatus::InvalidLifecycle ||
        notified == SourceLiveAccessLogNotifyStatus::InvalidRingIndex)
        session_->report_producer_fatal(
            SourceLiveAccessLogFatalKind::Protocol, ring_index_, EPROTO);
    return {SourceLiveAccessLogPublishStatus::Fatal, published.ticket};
}

void SourceLiveAccessLogProducer::fail_protocol(i32 system_error) {
    if (session_ != nullptr)
        session_->report_producer_fatal(
            SourceLiveAccessLogFatalKind::Protocol, ring_index_, system_error);
}

}  // namespace rut
