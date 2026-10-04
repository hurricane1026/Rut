#pragma once

#include "rut/common/types.h"

namespace rut {

enum class IoUringInitFailureDetail : u8 {
    None = 0,
    InvalidLifecycle,
    SendStateStorage,
    QueueSetup,
    QueueSetupFeatureFlagsUnsupported,
    SqRingMapping,
    SqeMapping,
    CqRingMapping,
    RingSizeInvariant,
    TerminalWindowMapping,
    TerminalSlotMapping,
    ProvidedBufferMapping,
    ProvidedBufferRingMapping,
    ProvidedBufferRingRegistration,
    ProvidedBufferRingUnsupported,
    TimerfdCreate,
    TimerfdSettime,
};

}  // namespace rut
