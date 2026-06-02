#pragma once

#include "rut/runtime/connection.h"

namespace rut {

enum ConnSlotMask : u8 {
    kConnSlotRecv = 1u << 0,
    kConnSlotSend = 1u << 1,
    kConnSlotUpstreamRecv = 1u << 2,
    kConnSlotUpstreamSend = 1u << 3,
};

enum ConnArmedMask : u8 {
    kConnArmedRecv = 1u << 0,
    kConnArmedSend = 1u << 1,
    kConnArmedUpstreamRecv = 1u << 2,
    kConnArmedUpstreamSend = 1u << 3,
    kConnArmedYield = 1u << 4,
};

struct ConnDebugSnapshot {
    u32 id = 0;
    i32 fd = -1;
    i32 upstream_fd = -1;
    ConnState state = ConnState::Idle;
    u8 slot_mask = 0;
    u8 armed_mask = 0;
    u32 pending_ops = 0;
    u16 resp_status = 0;
    u16 handler_state = 0;
    bool pending_handler = false;
    u32 recv_len = 0;
    u32 send_len = 0;
    u32 upstream_recv_len = 0;
};

inline const char* conn_state_name(ConnState state) {
    static constexpr const char* kConnStateNames[static_cast<u8>(ConnState::Count)] = {
        "Idle",
        "ReadingHeader",
        "ReadingBody",
        "ExecHandler",
        "Proxying",
        "Sending",
    };
    static_assert(
        sizeof(kConnStateNames) / sizeof(*kConnStateNames) == static_cast<u8>(ConnState::Count),
        "conn_state_name table must cover all ConnState values");

    const auto idx = static_cast<u8>(state);
    if (idx < static_cast<u8>(ConnState::Count)) {
        return kConnStateNames[idx];
    }
    return "Unknown";
}

inline u8 conn_slot_mask(const Connection& c) {
    u8 mask = 0;
    if (c.on_recv) mask |= kConnSlotRecv;
    if (c.on_send) mask |= kConnSlotSend;
    if (c.on_upstream_recv) mask |= kConnSlotUpstreamRecv;
    if (c.on_upstream_send) mask |= kConnSlotUpstreamSend;
    return mask;
}

inline u8 conn_armed_mask(const Connection& c) {
    u8 mask = 0;
    if (c.recv_armed) mask |= kConnArmedRecv;
    if (c.send_armed) mask |= kConnArmedSend;
    if (c.upstream_recv_armed) mask |= kConnArmedUpstreamRecv;
    if (c.upstream_send_armed) mask |= kConnArmedUpstreamSend;
    if (c.yield_armed) mask |= kConnArmedYield;
    return mask;
}

inline ConnDebugSnapshot make_conn_debug_snapshot(const Connection& c) {
    ConnDebugSnapshot s{};
    s.id = c.id;
    s.fd = c.fd;
    s.upstream_fd = c.upstream_fd;
    s.state = c.state;
    s.slot_mask = conn_slot_mask(c);
    s.armed_mask = conn_armed_mask(c);
    s.pending_ops = c.pending_ops;
    s.resp_status = c.resp_status;
    s.handler_state = c.handler_state;
    s.pending_handler = c.pending_handler_fn != nullptr;
    s.recv_len = c.recv_buf.len();
    s.send_len = c.send_buf.len();
    s.upstream_recv_len = c.upstream_recv_buf.len();
    return s;
}

struct DebugBufferWriter {
    char* out;
    u32 cap;
    u32 len;

    void put_char(char c) {
        if (cap > 0 && len + 1 < cap) out[len] = c;
        len++;
    }

    void put_cstr(const char* s) {
        for (u32 i = 0; s[i] != '\0'; i++) put_char(s[i]);
    }

    void put_u64(u64 v) {
        char tmp[20];
        u32 n = 0;
        do {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        } while (v != 0);
        while (n > 0) put_char(tmp[--n]);
    }

    void put_i32(i32 v) {
        if (v < 0) {
            put_char('-');
            put_u64(static_cast<u64>(-(v + 1)) + 1u);
        } else {
            put_u64(static_cast<u64>(v));
        }
    }

    u32 finish() {
        if (cap > 0) {
            const u32 pos = len < cap ? len : cap - 1;
            out[pos] = '\0';
        }
        return len;
    }
};

inline void format_conn_slot_mask(DebugBufferWriter& w, u8 mask) {
    if (mask == 0) {
        w.put_cstr("none");
        return;
    }
    bool first = true;
    auto put = [&](const char* name) {
        if (!first) w.put_char('|');
        w.put_cstr(name);
        first = false;
    };
    if (mask & kConnSlotRecv) put("recv");
    if (mask & kConnSlotSend) put("send");
    if (mask & kConnSlotUpstreamRecv) put("up_recv");
    if (mask & kConnSlotUpstreamSend) put("up_send");
}

inline void format_conn_armed_mask(DebugBufferWriter& w, u8 mask) {
    if (mask == 0) {
        w.put_cstr("none");
        return;
    }
    bool first = true;
    auto put = [&](const char* name) {
        if (!first) w.put_char('|');
        w.put_cstr(name);
        first = false;
    };
    if (mask & kConnArmedRecv) put("recv");
    if (mask & kConnArmedSend) put("send");
    if (mask & kConnArmedUpstreamRecv) put("up_recv");
    if (mask & kConnArmedUpstreamSend) put("up_send");
    if (mask & kConnArmedYield) put("yield");
}

inline u32 format_conn_debug_snapshot(const ConnDebugSnapshot& s, char* out, u32 out_size) {
    DebugBufferWriter w{out, out_size, 0};
    w.put_cstr("conn{id=");
    w.put_u64(s.id);
    w.put_cstr(" state=");
    w.put_cstr(conn_state_name(s.state));
    w.put_cstr(" fd=");
    w.put_i32(s.fd);
    w.put_cstr(" upstream_fd=");
    w.put_i32(s.upstream_fd);
    w.put_cstr(" slots=");
    format_conn_slot_mask(w, s.slot_mask);
    w.put_cstr(" armed=");
    format_conn_armed_mask(w, s.armed_mask);
    w.put_cstr(" pending_ops=");
    w.put_u64(s.pending_ops);
    w.put_cstr(" resp=");
    w.put_u64(s.resp_status);
    w.put_cstr(" handler=");
    if (s.pending_handler) {
        w.put_cstr("pending:");
        w.put_u64(s.handler_state);
    } else {
        w.put_cstr("none");
    }
    w.put_cstr(" recv_buf=");
    w.put_u64(s.recv_len);
    w.put_cstr(" send_buf=");
    w.put_u64(s.send_len);
    w.put_cstr(" upstream_recv_buf=");
    w.put_u64(s.upstream_recv_len);
    w.put_char('}');
    return w.finish();
}

inline u32 format_conn_debug(const Connection& c, char* out, u32 out_size) {
    return format_conn_debug_snapshot(make_conn_debug_snapshot(c), out, out_size);
}

}  // namespace rut
