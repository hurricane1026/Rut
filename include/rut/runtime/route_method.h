#pragma once

#include "rut/common/types.h"
#include "rut/runtime/access_log.h"
#include "rut/runtime/http_parser.h"

namespace rut {

// Route method keys are stable route-table storage values.
// 0 means "any"; known HTTP methods are stored as HttpMethod + 1 so
// HttpMethod::GET (0) does not collide with the any-method slot.
static constexpr u8 kRouteMethodAny = 0;
static constexpr u8 kRouteMethodGet = 1;
static constexpr u8 kRouteMethodPost = 2;
static constexpr u8 kRouteMethodPut = 3;
static constexpr u8 kRouteMethodDelete = 4;
static constexpr u8 kRouteMethodPatch = 5;
static constexpr u8 kRouteMethodHead = 6;
static constexpr u8 kRouteMethodOptions = 7;
static constexpr u8 kRouteMethodConnect = 8;
static constexpr u8 kRouteMethodTrace = 9;
static constexpr u32 kRouteMethodSlots = 10;
static constexpr u8 kRouteMethodInvalid = 0xffu;
static constexpr u32 kRouteMethodSlotInvalid = 0xffffffffu;

// Closed static-route admission set for the bounded complete-content-length
// response-buffering profile.  Keep this separate from the general route-key
// helpers: adding a future HTTP method must not silently widen buffering.
// TRACE is intentionally admitted only at request time through an ANY route.
inline bool complete_content_length_route_method_is_admitted(u8 method) {
    switch (method) {
        case kRouteMethodAny:
        case kRouteMethodGet:
        case kRouteMethodPost:
        case kRouteMethodPut:
        case kRouteMethodDelete:
        case kRouteMethodPatch:
        case kRouteMethodOptions:
            return true;
        default:
            return false;
    }
}

inline bool fixed_upload_head_route_method_is_admitted(u8 method) {
    return method == kRouteMethodAny || method == kRouteMethodHead;
}

inline u8 route_method_key(HttpMethod method) {
    switch (method) {
        case HttpMethod::GET:
            return kRouteMethodGet;
        case HttpMethod::POST:
            return kRouteMethodPost;
        case HttpMethod::PUT:
            return kRouteMethodPut;
        case HttpMethod::DELETE:
            return kRouteMethodDelete;
        case HttpMethod::PATCH:
            return kRouteMethodPatch;
        case HttpMethod::HEAD:
            return kRouteMethodHead;
        case HttpMethod::OPTIONS:
            return kRouteMethodOptions;
        case HttpMethod::CONNECT:
            return kRouteMethodConnect;
        case HttpMethod::TRACE:
            return kRouteMethodTrace;
        case HttpMethod::Unknown:
            return kRouteMethodInvalid;
    }
    return kRouteMethodInvalid;
}

inline u8 route_method_key(LogHttpMethod method) {
    switch (method) {
        case LogHttpMethod::Get:
            return kRouteMethodGet;
        case LogHttpMethod::Post:
            return kRouteMethodPost;
        case LogHttpMethod::Put:
            return kRouteMethodPut;
        case LogHttpMethod::Delete:
            return kRouteMethodDelete;
        case LogHttpMethod::Patch:
            return kRouteMethodPatch;
        case LogHttpMethod::Head:
            return kRouteMethodHead;
        case LogHttpMethod::Options:
            return kRouteMethodOptions;
        case LogHttpMethod::Connect:
            return kRouteMethodConnect;
        case LogHttpMethod::Trace:
            return kRouteMethodTrace;
        case LogHttpMethod::Other:
            // Preserve legacy runtime fallback behavior: malformed or
            // unrecognized requests can still hit an any-method catchall.
            return kRouteMethodAny;
    }
    return kRouteMethodInvalid;
}

inline u8 route_method_key_from_legacy_char(u8 method) {
    switch (method) {
        case 0:
            return kRouteMethodAny;
        case 'G':
            return kRouteMethodGet;
        case 'P':
            return kRouteMethodPost;
        case 'D':
            return kRouteMethodDelete;
        case 'H':
            return kRouteMethodHead;
        case 'O':
            return kRouteMethodOptions;
        case 'C':
            return kRouteMethodConnect;
        case 'T':
            return kRouteMethodTrace;
        default:
            return method;
    }
}

inline u32 route_method_slot_from_key(u8 method_key) {
    return method_key < kRouteMethodSlots ? method_key : kRouteMethodSlotInvalid;
}

inline u32 route_method_slot(u8 method_key_or_legacy_char) {
    const u8 key = route_method_key_from_legacy_char(method_key_or_legacy_char);
    return route_method_slot_from_key(key);
}

}  // namespace rut
