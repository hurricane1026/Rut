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
    ring_index_ = ring_index;
    return true;
}

void SourceLiveAccessLogProducer::reset() {
    ring_ = nullptr;
    session_ = nullptr;
    lease_ = nullptr;
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

void SourceLiveAccessLogProducer::fail_protocol(i32 system_error) {
    if (session_ != nullptr)
        session_->report_producer_fatal(
            SourceLiveAccessLogFatalKind::Protocol, ring_index_, system_error);
}

}  // namespace rut
