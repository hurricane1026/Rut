/*
 * Copyright (C) 2026 Rut Contributors
 *
 * This file is part of Rut.
 *
 * Rut is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Rut is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with Rut. If not, see <https://www.gnu.org/licenses/>.
 */

#include "rut/runtime/debug.h"
#include "test.h"

using namespace rut;

static void dummy_callback(void*, ConnectionBase&, IoEvent) {}

static u64 dummy_handler(void*, jit::HandlerCtx*, const u8*, u32, void*) {
    return 0;
}

TEST(debug, conn_state_name_all_values) {
    CHECK_STREQ(conn_state_name(ConnState::Idle), "Idle");
    CHECK_STREQ(conn_state_name(ConnState::ReadingHeader), "ReadingHeader");
    CHECK_STREQ(conn_state_name(ConnState::ReadingBody), "ReadingBody");
    CHECK_STREQ(conn_state_name(ConnState::ExecHandler), "ExecHandler");
    CHECK_STREQ(conn_state_name(ConnState::Proxying), "Proxying");
    CHECK_STREQ(conn_state_name(ConnState::Sending), "Sending");
}

TEST(debug, slot_and_armed_masks_reflect_connection_bits) {
    Connection c{};
    c.reset();
    CHECK_EQ(conn_slot_mask(c), 0u);
    CHECK_EQ(conn_armed_mask(c), 0u);

    c.on_recv = &dummy_callback;
    c.on_upstream_send = &dummy_callback;
    c.recv_armed = true;
    c.upstream_recv_armed = true;
    c.yield_armed = true;

    CHECK_EQ(conn_slot_mask(c), static_cast<u8>(kConnSlotRecv | kConnSlotUpstreamSend));
    CHECK_EQ(conn_armed_mask(c),
             static_cast<u8>(kConnArmedRecv | kConnArmedUpstreamRecv | kConnArmedYield));
}

TEST(debug, snapshot_captures_connection_debug_fields) {
    u8 recv_storage[64];
    u8 send_storage[64];
    u8 upstream_storage[64];
    Connection c{};
    c.reset();
    c.id = 17;
    c.fd = 42;
    c.upstream_fd = 100;
    c.state = ConnState::Proxying;
    c.on_recv = &dummy_callback;
    c.on_send = &dummy_callback;
    c.send_armed = true;
    c.pending_ops = 3;
    c.resp_status = 502;
    c.handler_state = 9;
    c.pending_handler_fn = &dummy_handler;
    c.recv_buf.bind(recv_storage, sizeof(recv_storage));
    c.send_buf.bind(send_storage, sizeof(send_storage));
    c.upstream_recv_buf.bind(upstream_storage, sizeof(upstream_storage));
    c.recv_buf.commit(5);
    c.send_buf.commit(7);
    c.upstream_recv_buf.commit(11);

    const auto s = make_conn_debug_snapshot(c);
    CHECK_EQ(s.id, 17u);
    CHECK_EQ(s.fd, 42);
    CHECK_EQ(s.upstream_fd, 100);
    CHECK_EQ(s.state, ConnState::Proxying);
    CHECK_EQ(s.slot_mask, static_cast<u8>(kConnSlotRecv | kConnSlotSend));
    CHECK_EQ(s.armed_mask, static_cast<u8>(kConnArmedSend));
    CHECK_EQ(s.pending_ops, 3u);
    CHECK_EQ(s.resp_status, 502u);
    CHECK_EQ(s.pending_handler, true);
    CHECK_EQ(s.handler_state, 9u);
    CHECK_EQ(s.recv_len, 5u);
    CHECK_EQ(s.send_len, 7u);
    CHECK_EQ(s.upstream_recv_len, 11u);
}

TEST(debug, format_conn_debug_snapshot_is_stable) {
    ConnDebugSnapshot s{};
    s.id = 7;
    s.fd = 42;
    s.upstream_fd = -1;
    s.state = ConnState::Sending;
    s.slot_mask = kConnSlotSend;
    s.armed_mask = static_cast<u8>(kConnArmedSend | kConnArmedYield);
    s.pending_ops = 2;
    s.resp_status = 204;
    s.pending_handler = true;
    s.handler_state = 3;
    s.recv_len = 10;
    s.send_len = 20;
    s.upstream_recv_len = 30;

    char buf[256];
    u32 n = format_conn_debug_snapshot(s, buf, sizeof(buf));
    CHECK_EQ(n, static_cast<u32>(__builtin_strlen(buf)));
    CHECK_STREQ(buf,
                "conn{id=7 state=Sending fd=42 upstream_fd=-1 slots=send "
                "armed=send|yield pending_ops=2 resp=204 handler=pending:3 "
                "recv_buf=10 send_buf=20 upstream_recv_buf=30}");
}

TEST(debug, format_conn_debug_truncates_and_reports_full_length) {
    ConnDebugSnapshot s{};
    s.id = 123;
    s.state = ConnState::ReadingHeader;

    char full[256];
    char small[12];
    u32 full_len = format_conn_debug_snapshot(s, full, sizeof(full));
    u32 small_len = format_conn_debug_snapshot(s, small, sizeof(small));

    CHECK_EQ(small_len, full_len);
    CHECK_EQ(small[sizeof(small) - 1], '\0');
    CHECK_STREQ(small, "conn{id=123");
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
