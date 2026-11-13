#include "rut/runtime/dns.h"

#include "rut/common/types.h"
#include "rut/platform/socket.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/poll.h>
#if defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__)
#include <sys/random.h>
#endif
#include <sys/socket.h>
#include <unistd.h>

namespace rut {
namespace {
u16 word(const u8* p) {
    return static_cast<u16>((p[0] << 8) | p[1]);
}
u32 number(const u8* p) {
    return (static_cast<u32>(word(p)) << 16) | word(p + 2);
}
void put(u8* p, u16 v) {
    p[0] = static_cast<u8>(v >> 8);
    p[1] = static_cast<u8>(v);
}
char lower(u8 c) {
    return static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c);
}
// Compression pointers must move backwards. Both jumps and expanded names are bounded.
bool name_at(const u8* p, u32 len, u32& offset, char* out) {
    u32 at = offset, used = 0, jumps = 0;
    bool jumped = false;
    for (u32 labels = 0; labels < 128; ++labels) {
        if (at >= len) return false;
        const u32 kStart = at;
        const u8 kN = p[at++];
        if ((kN & 0xc0) == 0xc0) {
            if (at >= len || ++jumps > 16) return false;
            const u32 kTarget = ((kN & 63u) << 8) | p[at++];
            if (kTarget < 12 || kTarget >= kStart) return false;
            if (!jumped) offset = at;
            jumped = true;
            at = kTarget;
            continue;
        }
        if (kN & 0xc0) return false;
        if (!kN) {
            if (!jumped) offset = at;
            out[used] = 0;
            return true;
        }
        if (at + kN > len || used + kN + (used ? 1u : 0u) > 253) return false;
        if (used) out[used++] = '.';
        for (u32 i = 0; i < kN; ++i) {
            const char kC = lower(p[at++]);
            if ((kC < 'a' || kC > 'z') && (kC < '0' || kC > '9') && kC != '-') return false;
            out[used++] = kC;
        }
    }
    return false;
}
bool pending() {
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
}
}  // namespace
bool dns_hostname(char* name) {
    u32 len = static_cast<u32>(strlen(name));
    if (len && name[len - 1] == '.') name[--len] = 0;
    if (!len || len > 253) return false;
    bool alphabetic = false;
    u32 label = 0;
    for (u32 i = 0; i <= len; ++i) {
        const char kC = lower(static_cast<u8>(name[i]));
        name[i] = kC;
        if (!kC || kC == '.') {
            if (!label || label > 63 || name[i - 1] == '-') return false;
            label = 0;
        } else {
            if (((kC < 'a' || kC > 'z') && (kC < '0' || kC > '9') && kC != '-') ||
                (!label && kC == '-'))
                return false;
            alphabetic |= kC >= 'a' && kC <= 'z';
            ++label;
        }
    }
    // Ambiguous numeric spellings must not become DNS names.
    return alphabetic;
}
u32 dns_question(const char* name, u16 id, u8* p, u32 capacity) {
    const u32 kLen = static_cast<u32>(strlen(name));
    if (capacity < kLen + 18) return 0;
    memset(p, 0, 12);
    put(p, id);
    put(p + 2, 0x0100);
    put(p + 4, 1);
    u32 at = 12, start = 0;
    for (u32 i = 0; i <= kLen; ++i) {
        if (name[i] && name[i] != '.') continue;
        const u32 kN = i - start;
        if (!kN || kN > 63) return 0;
        p[at++] = static_cast<u8>(kN);
        memcpy(p + at, name + start, kN);
        at += kN;
        start = i + 1;
    }
    p[at++] = 0;
    put(p + at, 1);
    put(p + at + 2, 1);
    return at + 4;
}
DnsAnswer dns_answer(const u8* p, u32 len, const char* name, u16 id, DnsResult& result) {
    result = {};
    if (len < 12 || word(p) != id || (word(p + 2) & 0xf840) != 0x8000 || word(p + 4) != 1)
        return DnsAnswer::Invalid;
    u32 at = 12;
    char question[254]{};
    if (!name_at(p, len, at, question) || strcmp(question, name) != 0 || at + 4 > len ||
        word(p + at) != 1 || word(p + at + 2) != 1)
        return DnsAnswer::Invalid;
    at += 4;
    if (word(p + 2) & 0x0200) return DnsAnswer::Truncated;
    if (word(p + 2) & 15) return DnsAnswer::Failure;
    const u32 kAnswers = word(p + 6), kTotal = kAnswers + word(p + 8) + word(p + 10);
    if (kTotal > 64) return DnsAnswer::Invalid;
    struct Record {
        char owner[254]{};
        u32 ttl = 0, data = 0;
        u16 type = 0, size = 0;
    };
    Record records[64]{};
    for (u32 i = 0; i < kTotal; ++i) {
        auto& r = records[i];
        if (!name_at(p, len, at, r.owner) || at + 10 > len) return DnsAnswer::Invalid;
        r.type = word(p + at + 2) == 1 ? word(p + at) : 0;
        r.ttl = number(p + at + 4);
        if (r.ttl & 0x80000000u) r.ttl = 0;
        r.size = word(p + at + 8);
        r.data = at + 10;
        at = r.data + r.size;
        if (at > len) return DnsAnswer::Invalid;
    }
    if (at != len) return DnsAnswer::Invalid;
    memcpy(result.canonical, name, strlen(name) + 1);
    for (u32 depth = 0; depth <= 8; ++depth) {
        bool alias = false;
        char target[254]{};
        for (u32 i = 0; i < kAnswers; ++i) {
            const auto& r = records[i];
            if (strcmp(r.owner, result.canonical) != 0) continue;
            if (r.type == 1) {
                if (r.size != 4) return DnsAnswer::Invalid;
                if (result.count < 8) memcpy(&result.addresses[result.count++], p + r.data, 4);
                if (r.ttl < result.ttl) result.ttl = r.ttl;
            } else if (r.type == 5) {
                u32 pos = r.data;
                char candidate[254]{};
                if (!name_at(p, len, pos, candidate) || pos != r.data + r.size ||
                    !dns_hostname(candidate) || (alias && strcmp(candidate, target) != 0))
                    return DnsAnswer::Invalid;
                memcpy(target, candidate, sizeof(target));
                alias = true;
                if (r.ttl < result.ttl) result.ttl = r.ttl;
            }
        }
        if (result.count) return alias ? DnsAnswer::Invalid : DnsAnswer::Addresses;
        if (!alias) return depth ? DnsAnswer::Alias : DnsAnswer::Failure;
        if (depth == 8 || !strcmp(target, result.canonical)) return DnsAnswer::Invalid;
        memcpy(result.canonical, target, sizeof(target));
    }
    return DnsAnswer::Invalid;
}
void DnsQuery::close() {
    if (fd >= 0) ::close(fd);
    fd = -1;
}
void DnsResolver::init() {
    memset(cache, 0, sizeof(cache));
    count = replacement = 0;
    // Cold worker initialization only. No NSS modules, search domains or implicit fallback.
    const int kFd = open("/etc/resolv.conf", O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (kFd < 0) return;
    char contents[4096]{};
    const auto kN = read(kFd, contents, sizeof(contents) - 1);
    ::close(kFd);
    if (kN <= 0) return;
    char* line = contents;
    while (*line && count < 3) {
        char* end = strchr(line, '\n');
        if (end) *end = 0;
        while (*line == ' ' || *line == '\t') ++line;
        if (!strncmp(line, "nameserver", 10) && (line[10] == ' ' || line[10] == '\t')) {
            line += 10;
            while (*line == ' ' || *line == '\t') ++line;
            char* tail = line;
            while (*tail && *tail != ' ' && *tail != '\t' && *tail != '#') ++tail;
            *tail = 0;
            in_addr ip{};
            if (inet_pton(AF_INET, line, &ip) == 1) servers[count++] = ip.s_addr;
        }
        if (!end) break;
        line = end + 1;
    }
}
int DnsResolver::resolve(
    DnsQuery& q, const char* host, u32 server, u16 port, u64 epoch, u64 now, u64& expires) {
    if (!q.phase) {
        for (auto& e : cache) {
            if (e.epoch != epoch || e.server != server || e.port != port || e.expires <= now ||
                strcmp(e.name, host) != 0)
                continue;
            q.result = e.result;
            const u32 kIndex = e.next++ % q.result.count;
            const u32 kFirst = q.result.addresses[0];
            q.result.addresses[0] = q.result.addresses[kIndex];
            q.result.addresses[kIndex] = kFirst;
            expires = e.expires;
            return 1;
        }
        q.valid_until = now + 60000;
        memcpy(q.name, host, strlen(host) + 1);
        q.phase = 1;
    }
    const u32 kAvailable = server ? 1 : count;
    auto retry = [&]() {
        q.close();
        q.sent = q.received = q.size = 0;
        q.phase = 1;
        return ++q.server < kAvailable ? 0 : -1;
    };
    if (!kAvailable) return -1;
    if (q.fd >= 0 && now - q.attempt >= 1000) return retry();
    if (q.phase == 1) {
#if defined(__linux__)
        if (getrandom(&q.id, sizeof(q.id), GRND_NONBLOCK) != sizeof(q.id)) return -1;
#else
        if (getentropy(&q.id, sizeof(q.id))) return -1;
#endif
        q.question_size = dns_question(q.name, q.id, q.question + 2, sizeof(q.question) - 2);
        if (!q.question_size) return -1;
        put(q.question, static_cast<u16>(q.question_size));
        q.fd = platform::datagram_socket();
        if (q.fd < 0) return -1;
        sockaddr_in peer{};
        peer.sin_family = AF_INET;
        peer.sin_port = htons(port);
        peer.sin_addr.s_addr = server ? server : servers[q.server];
        if (connect(q.fd, reinterpret_cast<sockaddr*>(&peer), sizeof(peer))) return retry();
        q.attempt = now;
        q.phase = 2;
    }
    if (q.fd < 0) return -1;
    if (q.phase == 2) {
        const auto kN = send(q.fd, q.question + 2, q.question_size, platform::kSendFlags);
        if (kN < 0 && pending()) return 0;
        if (kN != q.question_size) return retry();
        q.phase = 3;
        return 0;
    }
    u32 length = 0;
    if (q.phase == 3) {
        const auto kN = recv(q.fd, q.packet, 4096, MSG_TRUNC);
        if (kN < 0 && pending()) return 0;
        if (kN < 0 || kN > 4096) return retry();
        length = static_cast<u32>(kN);
    } else if (q.phase == 4) {
        pollfd ready{q.fd, POLLOUT, 0};
        const int kPolled = poll(&ready, 1, 0);
        if (kPolled < 0) return errno == EINTR ? 0 : retry();
        if (!kPolled) return 0;
        int error = 0;
        socklen_t size = sizeof(error);
        if (getsockopt(q.fd, SOL_SOCKET, SO_ERROR, &error, &size) || error) return retry();
        q.phase = 5;
        return 0;
    } else if (q.phase == 5) {
        const auto kN =
            send(q.fd, q.question + q.sent, q.question_size + 2 - q.sent, platform::kSendFlags);
        if (kN < 0 && pending()) return 0;
        if (kN <= 0) return retry();
        q.sent += static_cast<u32>(kN);
        if (q.sent == q.question_size + 2) q.phase = 6;
        return 0;
    } else if (q.phase == 6) {
        const u32 kTarget = q.received < 2 ? 2 : q.size + 2;
        const auto kN = recv(q.fd, q.packet + q.received, kTarget - q.received, 0);
        if (kN < 0 && pending()) return 0;
        if (kN <= 0) return retry();
        q.received += static_cast<u32>(kN);
        if (q.received == 2) {
            q.size = word(q.packet);
            if (q.size < 12 || q.size > 4096) return retry();
            return 0;
        }
        if (q.received != q.size + 2) return 0;
        length = q.size;
        memmove(q.packet, q.packet + 2, length);
    }
    DnsResult result;
    const auto kAnswer = dns_answer(q.packet, length, q.name, q.id, result);
    if (kAnswer == DnsAnswer::Invalid) return q.phase == 3 ? 0 : retry();
    if (kAnswer == DnsAnswer::Truncated && q.phase == 3) {
        q.close();
        q.fd = platform::stream_socket();
        if (q.fd < 0) return retry();
        sockaddr_in peer{};
        peer.sin_family = AF_INET;
        peer.sin_port = htons(port);
        peer.sin_addr.s_addr = server ? server : servers[q.server];
        if (connect(q.fd, reinterpret_cast<sockaddr*>(&peer), sizeof(peer)) && errno != EINPROGRESS)
            return retry();
        q.phase = 4;
        return 0;
    }
    if (kAnswer != DnsAnswer::Addresses && kAnswer != DnsAnswer::Alias) return retry();
    const u64 kValidUntil = now + static_cast<u64>(result.ttl) * 1000;
    if (kValidUntil < q.valid_until) q.valid_until = kValidUntil;
    if (result.ttl < q.result.ttl) q.result.ttl = result.ttl;
    if (kAnswer == DnsAnswer::Alias) {
        if (++q.aliases > 8) {
            q.close();
            return -1;
        }
        memcpy(q.name, result.canonical, sizeof(q.name));
        q.close();
        q.phase = 1;
        q.sent = q.received = q.size = 0;
        return 0;
    }
    result.ttl = q.result.ttl;
    q.result = result;
    q.close();
    expires = q.valid_until;
    if (result.ttl && expires > now) {
        auto& e = cache[replacement++ % 16];
        e = {};
        memcpy(e.name, host, strlen(host) + 1);
        e.server = server;
        e.port = port;
        e.epoch = epoch;
        e.expires = expires;
        e.result = result;
        e.next = 1;
    }
    return 1;
}
}  // namespace rut
