#pragma once
#include "rut/common/types.h"

namespace rut {
// Bounded IPv4 stub resolver. All methods belong to the network worker.
// No libc resolver, heap allocation, background thread or shard blocking.
bool dns_hostname(char* name);
struct DnsResult {
    u32 addresses[8]{};  // network byte order
    u32 count = 0;
    u32 ttl = 60;
    char canonical[254]{};
};
enum class DnsAnswer : u8 { Invalid, Truncated, Failure, Alias, Addresses };
u32 dns_question(const char* name, u16 id, u8* packet, u32 capacity);
DnsAnswer dns_answer(const u8* packet, u32 length, const char* name, u16 id, DnsResult& result);
struct DnsQuery {
    int fd = -1;
    u8 phase = 0, server = 0, aliases = 0;
    u16 id = 0;
    u32 sent = 0, received = 0, size = 0, question_size = 0;
    u64 attempt = 0, valid_until = 0;
    char name[254]{};
    u8 question[274]{};
    u8 packet[4098]{};
    DnsResult result{};
    void close();
};
class DnsResolver {
public:
    void init();
    // 0 pending, 1 resolved, -1 failed. Caller enforces the overall deadline.
    int resolve(DnsQuery& query,
                const char* hostname,
                u32 server,
                u16 port,
                u64 epoch,
                u64 now,
                u64& expires);

private:
    struct Entry {
        char name[254]{};
        u32 server = 0, next = 0;
        u16 port = 0;
        u64 epoch = 0, expires = 0;
        DnsResult result{};
    };
    Entry cache[16]{};
    u32 servers[3]{}, count = 0, replacement = 0;
};
}  // namespace rut
