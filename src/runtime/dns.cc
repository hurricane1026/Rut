#include "rut/runtime/dns.h"

#include "rut/common/checked_arithmetic.h"
#include "rut/common/range_int.h"
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
    return (range_int(p[0]).scaled_by<256>() + range_int(p[1])).to<u16>();
}
u32 number(const u8* p) {
    return (range_int{word(p)}.scaled_by<65536>() + range_int{word(p + 2)}).to<u32>();
}
void put(u8* p, u16 v) {
    p[0] = range_int(v).divided_by<256>().to<u8>();
    p[1] = bounded_remainder<256>(v).to<u8>();
}
[[nodiscard]] u8 lower(u8 c) {
    range_int<'A', 'Z' + 1> upper;
    if (!decltype(upper)::try_from_u64(c, &upper)) return c;
    return (upper + range_int<'a' - 'A', 'a' - 'A' + 1>{}).to<u8>();
}
// Compression pointers must move backwards. Both jumps and expanded names are bounded.
[[nodiscard]] bool name_at(const u8* p, u32 len, u32* offset, char (&out)[254]) {
    u32 at = *offset, used = 0, jumps = 0;
    u32 compressed_end = 0;
    auto* output = reinterpret_cast<u8*>(out);
    const auto wire_size = range_int{len};
    for (u32 labels = 0; labels < 128; ++labels) {
        if (at >= len) return false;
        const u32 kStart = at;
        const u8 kN = p[at++];
        if ((kN & 0xc0) == 0xc0) {
            if (at >= len || ++jumps > 16) return false;
            const auto high = bounded_remainder<64>(kN).scaled_by<256>();
            const u32 kTarget = (high + range_int{p[at++]}).to<u32>();
            if (kTarget < 12 || kTarget >= kStart) return false;
            if (compressed_end == 0) compressed_end = at;
            at = kTarget;
            continue;
        }
        if (kN & 0xc0) return false;
        if (!kN) {
            *offset = compressed_end == 0 ? at : compressed_end;
            output[used] = 0;
            return true;
        }
        const auto label = range_int{kN};
        const auto cursor = range_int{at};
        const auto destination = range_int{used};
        const auto separator = range_int{u8{used != 0}};
        if ((cursor + label).value() > wire_size.value() ||
            (destination + label + separator).value() >= sizeof(out))
            return false;
        if (used) output[used++] = '.';
        for (u32 i = 0; i < kN; ++i) {
            const u8 kC = lower(p[at++]);
            if ((kC < 'a' || kC > 'z') && (kC < '0' || kC > '9') && kC != '-') return false;
            output[used++] = kC;
        }
    }
    return false;
}
bool pending() {
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
}
// DNS names have at most 253 characters plus a terminator.
bool copy_dns_name(char (&destination)[254], const char* source) {
    if (!source) return false;
    range_int<0, sizeof(destination)> len;
    if (!decltype(len)::try_from_u64(strnlen(source, sizeof(destination)), &len)) return false;
    constexpr auto kTerminatorSize = range_int<1, 2>::constant<1>();
    memcpy(destination, source, (len + kTerminatorSize).to_u64());
    return true;
}
}  // namespace
bool dns_hostname(char* name) {
    // Allow one extra character for the final root dot.
    range_int<1, 255> length;
    if (!name || !decltype(length)::try_from_u64(strnlen(name, 255), &length)) return false;
    const auto kLast = length - range_int<1, 2>{};
    const bool kRootDot = name[kLast.index()] == '.';
    const i64 len = kRootDot ? kLast.value() : length.value();
    if (kRootDot) name[kLast.index()] = 0;
    if (!len || len > 253) return false;
    bool alphabetic = false;
    u32 label = 0;
    auto* bytes = reinterpret_cast<u8*>(name);
    for (u32 i = 0; i <= len; ++i) {
        const u8 kC = lower(bytes[i]);
        bytes[i] = kC;
        if (!kC || kC == '.') {
            if (!label || label > 63 || *(bytes + range_int{i}.index() - 1) == '-') return false;
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
    if (!name || !p || capacity < 18) return 0;
    range_int<0, UINT32_MAX + 1LL> name_length;
    if (!decltype(name_length)::try_from_u64(strnlen(name, capacity), &name_length) ||
        (name_length + range_int<18, 19>{}).value() > capacity)
        return 0;
    const u32 kLen = name_length.to<u32>();
    memset(p, 0, 12);
    put(p, id);
    put(p + 2, 0x0100);
    put(p + 4, 1);
    const auto limit = range_int{capacity};
    u32 at = 12, start = 0;
    for (u32 i = 0; i <= kLen; ++i) {
        if (name[i] && name[i] != '.') continue;
        range_int<1, 64> label;
        if (!decltype(label)::try_from_i64((range_int(i) - range_int(start)).value(), &label))
            return 0;
        const u8 kN = label.to<u8>();
        const auto cursor = range_int{at};
        const auto label_start = cursor + range_int<1, 2>{};
        auto end = cursor;
        if (!limit.try_count((label_start + label).value(), &end)) return 0;
        p[cursor.index()] = kN;
        memcpy(p + label_start.index(), name + range_int{start}.index(), kN);
        at = end.to<u32>();
        if (!(range_int{i} + range_int<1, 2>{}).to(&start)) return 0;
    }
    const auto cursor = range_int{at};
    auto end = cursor;
    if (!limit.try_count((cursor + range_int<5, 6>{}).value(), &end)) return 0;
    u8* const trailer = p + cursor.index();
    trailer[0] = 0;
    put(trailer + 1, 1);
    put(trailer + 3, 1);
    return end.to<u32>();
}
DnsAnswer dns_answer(const u8* p, u32 len, const char* name, u16 id, DnsResult& result) {
    result = {};
    if (len < 12 || word(p) != id || (word(p + 2) & 0xf840) != 0x8000 || word(p + 4) != 1)
        return DnsAnswer::Invalid;
    u32 at = 12;
    char question[254]{};
    if (!name_at(p, len, &at, question) || strcmp(question, name) != 0 ||
        (range_int{at} + range_int<4, 5>{}).value() > len || word(p + range_int{at}.index()) != 1 ||
        word(p + (range_int{at} + range_int<2, 3>{}).index()) != 1)
        return DnsAnswer::Invalid;
    at = (range_int(at) + range_int<4, 5>{}).min(range_int(len)).to<u32>();
    if (word(p + 2) & 0x0200) return DnsAnswer::Truncated;
    if (word(p + 2) & 15) return DnsAnswer::Failure;
    const u16 kAnswers = word(p + 6);
    const auto kCount = range_int(kAnswers) + range_int(word(p + 8)) + range_int(word(p + 10));
    const u32 kTotal = kCount.to<u32>();
    if (kTotal > 64) return DnsAnswer::Invalid;
    struct Record {
        char owner[254]{};
        u32 ttl = 0, data = 0;
        u16 type = 0, size = 0;
    };
    Record records[64]{};
    for (u32 i = 0; i < kTotal; ++i) {
        auto& r = records[i];
        if (!name_at(p, len, &at, r.owner)) return DnsAnswer::Invalid;
        const auto cursor = range_int{at};
        const auto data = cursor + range_int<10, 11>{};
        if (data.value() > len) return DnsAnswer::Invalid;
        r.data = data.min(range_int(len)).to<u32>();
        const u8* const fields = p + cursor.index();
        r.type = word(fields + 2) == 1 ? word(fields) : 0;
        r.ttl = number(fields + 4);
        if (r.ttl & 0x80000000u) r.ttl = 0;
        r.size = word(fields + 8);
        const auto end = data + range_int(r.size);
        if (end.value() > len) return DnsAnswer::Invalid;
        at = end.min(range_int(len)).to<u32>();
    }
    if (at != len) return DnsAnswer::Invalid;
    if (!copy_dns_name(result.canonical, name)) return DnsAnswer::Invalid;
    for (u32 depth = 0; depth <= 8; ++depth) {
        bool alias = false;
        char target[254]{};
        for (u32 i = 0; i < kAnswers; ++i) {
            const auto& r = records[i];
            if (strcmp(r.owner, result.canonical) != 0) continue;
            if (r.type == 1) {
                if (r.size != 4) return DnsAnswer::Invalid;
                u32 address = 0;
                memcpy(&address, p + range_int{r.data}.index(), 4);
                bool duplicate = false;
                for (u32 j = 0; j < result.count; ++j) duplicate |= result.addresses[j] == address;
                if (!duplicate) {
                    if (result.count < 8) {
                        result.addresses[result.count] = address;
                        result.count = (range_int(result.count) + range_int<1, 2>{})
                                           .min(range_int<8, 9>{})
                                           .to<u32>();
                    } else {
                        result.overflow = true;
                    }
                }
                if (r.ttl < result.ttl) result.ttl = r.ttl;
            } else if (r.type == 5) {
                u32 pos = r.data;
                char candidate[254]{};
                const auto end = range_int{r.data} + range_int{r.size};
                if (!name_at(p, len, &pos, candidate) || pos != end.value() ||
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
    if (!host) return -1;
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
        if (!copy_dns_name(q.name, host)) return -1;
        u64 next_valid = 0;
        q.valid_until = add_overflow(now, u64{60000}, &next_valid) ? ~u64{0} : next_valid;
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
    u64 attempt_age = 0;
    if (q.fd >= 0 && (sub_overflow(now, q.attempt, &attempt_age) || attempt_age >= 1000))
        return retry();
    if (q.phase == 1) {
#if defined(__linux__)
        if (getrandom(&q.id, sizeof(q.id), GRND_NONBLOCK) != sizeof(q.id)) return -1;
#else
        if (getentropy(&q.id, sizeof(q.id))) return -1;
#endif
        q.question_size = dns_question(q.name, q.id, q.question + 2, sizeof(q.question) - 2);
        if (!q.question_size) return -1;
        range_int<1, sizeof(q.question) - 1> length;
        if (!decltype(length)::try_from_i64(q.question_size, &length)) return -1;
        put(q.question, length.to<u16>());
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
        range_int<0, 4097> received;
        if (!decltype(received)::try_from_i64(kN, &received)) return retry();
        length = received.to<u32>();
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
        using QuestionLength = range_int<0, sizeof(q.question) + 1>;
        QuestionLength target;
        QuestionLength pending_bytes;
        const auto sent = range_int{q.sent};
        if (!QuestionLength::try_from_i64((range_int{q.question_size} + range_int<2, 3>{}).value(),
                                          &target) ||
            !target.try_count((target - sent).value(), &pending_bytes) ||
            pending_bytes.value() == 0)
            return retry();
        const auto kN =
            send(q.fd, q.question + sent.index(), pending_bytes.to_u64(), platform::kSendFlags);
        if (kN < 0 && pending()) return 0;
        QuestionLength written, next;
        if (kN <= 0 || !pending_bytes.try_count(kN, &written) ||
            !target.try_count((sent + written).value(), &next))
            return retry();
        q.sent = next.to<u32>();
        if (q.sent == target.value()) q.phase = 6;
        return 0;
    } else if (q.phase == 6) {
        using PacketLength = range_int<0, sizeof(q.packet) + 1>;
        const auto received = range_int{q.received};
        constexpr auto kPrefixSize = range_int<2, 3>{};
        const auto packet_size = range_int{q.size} + kPrefixSize;
        PacketLength target;
        PacketLength pending_bytes;
        if (!PacketLength::try_from_i64(q.received < 2 ? kPrefixSize.value() : packet_size.value(),
                                        &target) ||
            !target.try_count((target - received).value(), &pending_bytes) ||
            pending_bytes.value() == 0)
            return retry();
        const auto kN = recv(q.fd, q.packet + received.index(), pending_bytes.to_u64(), 0);
        if (kN < 0 && pending()) return 0;
        PacketLength read, next;
        if (kN <= 0 || !pending_bytes.try_count(kN, &read) ||
            !target.try_count((received + read).value(), &next))
            return retry();
        q.received = next.to<u32>();
        if (q.received == 2) {
            q.size = word(q.packet);
            if (q.size < 12 || q.size > 4096) return retry();
            return 0;
        }
        if (next.value() != packet_size.value()) return 0;
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
    const u64 ttl_ms = range_int(result.ttl).scaled_by<1000>().to_u64();
    u64 kValidUntil = 0;
    if (add_overflow(now, ttl_ms, &kValidUntil)) kValidUntil = ~u64{0};
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
        if (copy_dns_name(e.name, host)) {
            e.server = server;
            e.port = port;
            e.epoch = epoch;
            e.expires = expires;
            e.result = result;
            e.next = 1;
        }
    }
    return 1;
}
}  // namespace rut
