#include "rut/platform/socket.h"
#include "rut/runtime/dns.h"
#include "rut/runtime/https_fetch.h"
#include "rut/runtime/net_client.h"
#include "test.h"

#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
using namespace rut;
namespace {
void put(u8* p, u16 v) {
    p[0] = static_cast<u8>(v >> 8);
    p[1] = static_cast<u8>(v);
}
u32 response(u8* p, u32 length, u16 type = 1, u32 ttl = 1) {
    put(p + 2, 0x8180);
    put(p + 6, 1);
    const u8 record[] = {0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 127, 0, 0, 1};
    memcpy(p + length, record, sizeof(record));
    put(p + length + 2, type);
    p[length + 9] = static_cast<u8>(ttl);
    return length + sizeof(record);
}
struct Peer {
    int udp = -1, tcp = -1;
    u16 port = 0;
    pthread_t thread{};
    u32 stopped = 0, queries = 0, tcp_queries = 0;
    bool truncation = false, silence = false, nxdomain = false, alias = false, multiple = false;
    u32 ttl = 1;
    bool start() {
        // Reserve TCP first: a UDP-selected ephemeral port can already be in
        // TCP TIME_WAIT or belong to another concurrently running fixture.
        for (u32 attempt = 0; attempt < 16; ++attempt) {
            udp = platform::datagram_socket();
            tcp = platform::stream_socket();
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            if (udp < 0 || tcp < 0) return false;
            if (!bind(tcp, reinterpret_cast<sockaddr*>(&addr), sizeof(addr))) {
                socklen_t size = sizeof(addr);
                if (!getsockname(tcp, reinterpret_cast<sockaddr*>(&addr), &size) &&
                    !bind(udp, reinterpret_cast<sockaddr*>(&addr), sizeof(addr))) {
                    port = ntohs(addr.sin_port);
                    return !listen(tcp, 16) && !pthread_create(&thread, nullptr, run, this);
                }
            }
            close(udp);
            close(tcp);
            udp = tcp = -1;
        }
        return false;
    }
    ~Peer() {
        __atomic_store_n(&stopped, 1u, __ATOMIC_RELEASE);
        if (thread) pthread_join(thread, nullptr);
        if (udp >= 0) close(udp);
        if (tcp >= 0) close(tcp);
    }
    static void* run(void* context) {
        auto& p = *static_cast<Peer*>(context);
        while (!__atomic_load_n(&p.stopped, __ATOMIC_ACQUIRE)) {
            u8 packet[512]{};
            sockaddr_in from{};
            socklen_t size = sizeof(from);
            const auto n = recvfrom(
                p.udp, packet, sizeof(packet), 0, reinterpret_cast<sockaddr*>(&from), &size);
            if (n > 12) {
                __atomic_add_fetch(&p.queries, 1u, __ATOMIC_RELAXED);
                if (!p.silence) {
                    u32 length = response(packet, static_cast<u32>(n), 1, p.ttl);
                    if (p.alias && packet[12] == 5 && !memcmp(packet + 13, "cache", 5)) {
                        const u8 cname[] = {0xc0, 12,  0,   5,   0,   1,   0,   0,   0,
                                            0,    0,   15,  5,   'a', 'l', 'i', 'a', 's',
                                            7,    'e', 'x', 'a', 'm', 'p', 'l', 'e', 0};
                        memcpy(packet + n, cname, sizeof(cname));
                        length = static_cast<u32>(n) + sizeof(cname);
                    }
                    if (p.multiple) {
                        // First destination refuses connections; second succeeds.
                        packet[length - 1] = 2;
                        memcpy(packet + length, packet + n, 16);
                        packet[length + 15] = 1;
                        length += 16;
                        put(packet + 6, 2);
                    }
                    if (p.truncation) {
                        put(packet + 2, 0x8380);
                        put(packet + 6, 0);
                        length = static_cast<u32>(n);
                    }
                    if (p.nxdomain) {
                        put(packet + 2, 0x8183);
                        put(packet + 6, 0);
                        length = static_cast<u32>(n);
                    }
                    sendto(p.udp, packet, length, 0, reinterpret_cast<sockaddr*>(&from), size);
                }
            }
            const int client = accept(p.tcp, nullptr, nullptr);
            if (client >= 0) {
                // Fixtures use bounded reads even if the client is cancelled.
                timeval timeout{0, 200000};
                setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                u8 prefix[2]{};
                if (recv(client, prefix, 2, MSG_WAITALL) == 2) {
                    const u32 length = (prefix[0] << 8) | prefix[1];
                    if (length <= sizeof(packet) - 16 &&
                        recv(client, packet, length, MSG_WAITALL) == length) {
                        __atomic_add_fetch(&p.tcp_queries, 1u, __ATOMIC_RELAXED);
                        const u32 reply = response(packet, length);
                        put(prefix, static_cast<u16>(reply));
                        send(client, prefix, 1, platform::kSendFlags);
                        send(client, prefix + 1, 1, platform::kSendFlags);
                        for (u32 i = 0; i < reply; ++i)
                            send(client, packet + i, 1, platform::kSendFlags);
                    }
                }
                close(client);
            }
            usleep(1000);
        }
        return nullptr;
    }
};
int resolve(DnsResolver& r, DnsQuery& q, u16 port, u64& expires, u64 epoch = 1) {
    for (u32 i = 0; i < 1500; ++i) {
        const int status = r.resolve(
            q, "cache.example", htonl(INADDR_LOOPBACK), port, epoch, jwt_monotonic_ms(), expires);
        if (status) return status;
        usleep(1000);
    }
    q.close();
    return -2;
}
NetReply call(NetClientWorker& w,
              NetOp op,
              u32 owner,
              u32 handle,
              const NetEndpoint* endpoint,
              u32 timeout = 500) {
    for (u32 i = 0; i < 1000; ++i) {
        auto result = w.call(owner, 1, op, handle, endpoint, {}, 0, jwt_monotonic_ms(), timeout);
        if (result.status != NetReply::kPending) return result;
        usleep(1000);
    }
    return {};
}
}  // namespace
TEST(dns, hostname_policy_normalizes_and_rejects_ambiguous_or_dynamic_targets) {
    NetEndpoint e;
    CHECK(net_endpoint(
        lit_str(
            R"({"address":"Redis.Example.","port":6379,"dnsServer":"127.0.0.1","dnsPort":1053})"),
        false,
        e));
    CHECK_EQ(strcmp(e.address, "redis.example"), 0);
    CHECK(net_endpoint(lit_str(R"({"address":"localhost","port":6379})"), true, e));
    const char* invalid[] = {"-x.example",
                             "x-.example",
                             "x..example",
                             "a_b",
                             "127.0.0.999",
                             "::1",
                             "https://example",
                             ".",
                             "x/a"};
    for (auto name : invalid) {
        char policy[512];
        snprintf(policy, sizeof(policy), "{\"address\":\"%s\",\"port\":1}", name);
        CHECK(!net_endpoint({policy, static_cast<u32>(strlen(policy))}, false, e));
    }
    CHECK(!net_endpoint(lit_str(R"({"address":"a.example","port":1,"dnsPort":53})"), false, e));
    CHECK(!net_endpoint(
        lit_str(R"({"address":"a.example","port":1,"dnsServer":"other.example"})"), false, e));
}
TEST(dns, parser_binds_id_question_and_owner_and_rejects_bad_compression) {
    u8 packet[512]{};
    const u32 n = dns_question("cache.example", 123, packet, sizeof(packet));
    REQUIRE(n > 12);
    const u32 len = response(packet, n);
    DnsResult result;
    CHECK(dns_answer(packet, len, "cache.example", 123, result) == DnsAnswer::Addresses);
    CHECK_EQ(result.count, 1u);
    CHECK_EQ(result.ttl, 1u);
    CHECK(dns_answer(packet, len, "cache.example", 124, result) == DnsAnswer::Invalid);
    CHECK(dns_answer(packet, len, "other.example", 123, result) == DnsAnswer::Invalid);
    for (u32 truncated = 0; truncated < len; ++truncated)
        CHECK(dns_answer(packet, truncated, "cache.example", 123, result) != DnsAnswer::Addresses);
    packet[n + 6] = 0x80;  // RFC 2181: TTL with its high bit set is zero.
    CHECK(dns_answer(packet, len, "cache.example", 123, result) == DnsAnswer::Addresses);
    CHECK_EQ(result.ttl, 0u);
    packet[n + 1] = static_cast<u8>(n);  // self-pointer
    CHECK(dns_answer(packet, len, "cache.example", 123, result) == DnsAnswer::Invalid);
}
TEST(dns, parser_cname_reordering_ttl_and_unrelated_glue) {
    u8 packet[512]{};
    const u32 n = dns_question("cache.example", 9, packet, sizeof(packet));
    // A for alias.example precedes CNAME cache.example -> alias.example.
    put(packet + 2, 0x8180);
    put(packet + 6, 2);
    u32 at = n;
    packet[at++] = 5;
    memcpy(packet + at, "alias", 5);
    at += 5;
    packet[at++] = 0xc0;
    packet[at++] = 18;
    put(packet + at, 1);
    put(packet + at + 2, 1);
    memset(packet + at + 4, 0, 4);
    packet[at + 7] = 20;
    put(packet + at + 8, 4);
    at += 10;
    packet[at++] = 127;
    packet[at++] = 0;
    packet[at++] = 0;
    packet[at++] = 1;
    packet[at++] = 0xc0;
    packet[at++] = 12;
    put(packet + at, 5);
    put(packet + at + 2, 1);
    memset(packet + at + 4, 0, 4);
    packet[at + 7] = 2;
    put(packet + at + 8, 2);
    at += 10;
    packet[at++] = 0xc0;
    packet[at++] = static_cast<u8>(n);
    DnsResult result;
    CHECK(dns_answer(packet, at, "cache.example", 9, result) == DnsAnswer::Addresses);
    CHECK_EQ(result.ttl, 2u);
    CHECK_EQ(strcmp(result.canonical, "alias.example"), 0);
    put(packet + 6, 1);
    put(packet + 10, 1);  // CNAME in additional section cannot authorize the A.
    CHECK(dns_answer(packet, at, "cache.example", 9, result) == DnsAnswer::Failure);
}
TEST(dns, udp_tcp_fallback_cache_and_config_epoch) {
    Peer peer;
    peer.truncation = true;
    REQUIRE(peer.start());
    DnsResolver resolver;
    resolver.init();
    DnsQuery query;
    u64 expires = 0;
    REQUIRE(resolve(resolver, query, peer.port, expires) == 1);
    CHECK_EQ(query.result.count, 1u);
    CHECK(expires > jwt_monotonic_ms());
    CHECK_EQ(__atomic_load_n(&peer.tcp_queries, __ATOMIC_RELAXED), 1u);
    const auto count = __atomic_load_n(&peer.queries, __ATOMIC_RELAXED);
    DnsQuery cached;
    REQUIRE(resolve(resolver, cached, peer.port, expires) == 1);
    CHECK_EQ(__atomic_load_n(&peer.queries, __ATOMIC_RELAXED), count);
    DnsQuery retired;
    REQUIRE(resolve(resolver, retired, peer.port, expires, 2) == 1);
    CHECK(__atomic_load_n(&peer.queries, __ATOMIC_RELAXED) > count);
}
TEST(dns, cname_followup_zero_ttl_and_nxdomain_are_not_cached) {
    Peer peer;
    peer.alias = true;
    REQUIRE(peer.start());
    DnsResolver resolver;
    resolver.init();
    DnsQuery query;
    u64 expires = 0;
    REQUIRE(resolve(resolver, query, peer.port, expires) == 1);
    CHECK_EQ(query.result.ttl, 0u);
    CHECK_EQ(__atomic_load_n(&peer.queries, __ATOMIC_RELAXED), 2u);
    DnsQuery again;
    REQUIRE(resolve(resolver, again, peer.port, expires) == 1);
    CHECK_EQ(__atomic_load_n(&peer.queries, __ATOMIC_RELAXED), 4u);
    Peer negative;
    negative.nxdomain = true;
    REQUIRE(negative.start());
    DnsQuery missing;
    CHECK_EQ(resolve(resolver, missing, negative.port, expires), -1);
    DnsQuery absent;
    CHECK_EQ(resolve(resolver, absent, negative.port, expires), -1);
    CHECK_EQ(__atomic_load_n(&negative.queries, __ATOMIC_RELAXED), 2u);
}
TEST(dns, worker_deadline_cancel_and_restart_release_resolver_sockets) {
    Peer peer;
    peer.silence = true;
    REQUIRE(peer.start());
    NetEndpoint e;
    REQUIRE(net_endpoint(
        lit_str(R"({"address":"cache.example","port":1,"dnsServer":"127.0.0.1"})"), false, e));
    e.dns_port = peer.port;
    NetClientWorker w;
    REQUIRE(w.start().has_value());
    CHECK_EQ(call(w, NetOp::Tcp, 1, 0, &e, 30).status, -2);
    auto pending = w.call(2, 1, NetOp::Tcp, 0, &e, {}, 0, jwt_monotonic_ms(), 500);
    CHECK_EQ(pending.status, NetReply::kPending);
    w.cancel(2, 1);
    w.stop();
    REQUIRE(w.start().has_value());
    CHECK_EQ(call(w, NetOp::Udp, 3, 0, &e, 30).status, -2);
    w.stop();
}
TEST(dns, ttl_expiry_retires_pooled_connection_and_zero_ttl_never_parks) {
    Peer peer;
    peer.multiple = true;
    REQUIRE(peer.start());
    const int listener = socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(listener >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(!bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)));
    REQUIRE(!listen(listener, 8));
    socklen_t size = sizeof(address);
    REQUIRE(!getsockname(listener, reinterpret_cast<sockaddr*>(&address), &size));
    NetEndpoint e;
    REQUIRE(net_endpoint(
        lit_str(
            R"({"address":"cache.example","port":1,"dnsServer":"127.0.0.1","poolIdleMs":60000})"),
        false,
        e));
    e.port = ntohs(address.sin_port);
    e.dns_port = peer.port;
    NetClientWorker w;
    REQUIRE(w.start().has_value());
    auto first = call(w, NetOp::Tcp, 1, 0, &e);
    REQUIRE(first.status == 0);
    int client = accept(listener, nullptr, nullptr);
    REQUIRE(client >= 0);
    CHECK_EQ(call(w, NetOp::Release, 1, first.scalar, nullptr).scalar, 1u);
    auto second = call(w, NetOp::Tcp, 2, 0, &e);
    REQUIRE(second.status == 0);
    CHECK_EQ(__atomic_load_n(&peer.queries, __ATOMIC_RELAXED), 1u);
    CHECK_EQ(call(w, NetOp::Release, 2, second.scalar, nullptr).scalar, 1u);
    usleep(1100000);
    auto third = call(w, NetOp::Tcp, 3, 0, &e);
    REQUIRE(third.status == 0);
    CHECK_EQ(__atomic_load_n(&peer.queries, __ATOMIC_RELAXED), 2u);
    pollfd closed{client, POLLIN, 0};
    REQUIRE(poll(&closed, 1, 200) > 0);
    char byte;
    CHECK_EQ(recv(client, &byte, 1, 0), 0);
    close(client);
    client = accept(listener, nullptr, nullptr);
    REQUIRE(client >= 0);
    w.stop();
    close(client);
    Peer zero;
    zero.ttl = 0;
    REQUIRE(zero.start());
    e.dns_port = zero.port;
    REQUIRE(w.start().has_value());
    auto zero_tcp = call(w, NetOp::Tcp, 4, 0, &e);
    REQUIRE(zero_tcp.status == 0);
    client = accept(listener, nullptr, nullptr);
    REQUIRE(client >= 0);
    CHECK_EQ(call(w, NetOp::Release, 4, zero_tcp.scalar, nullptr).scalar, 0u);
    close(client);
    auto again = call(w, NetOp::Tcp, 5, 0, &e);
    REQUIRE(again.status == 0);
    CHECK_EQ(__atomic_load_n(&zero.queries, __ATOMIC_RELAXED), 2u);
    client = accept(listener, nullptr, nullptr);
    REQUIRE(client >= 0);
    w.stop();
    close(client);
    close(listener);
}
int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
