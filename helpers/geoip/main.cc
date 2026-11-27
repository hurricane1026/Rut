#include "rut/common/range_int.h"
#include "rut/runtime/parse_integer.h"
#include "rut/runtime/parse_ip.h"

#include <errno.h>
#include <maxminddb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace rut;

static Str country(const MMDB_s& database, Str text) {
    u32 address;
    if (!parse_ipv4_address(text, address)) return {};

    sockaddr_in query{};
    query.sin_family = AF_INET;
    query.sin_addr.s_addr = address;
    int status;
    auto result =
        MMDB_lookup_sockaddr(&database, reinterpret_cast<const sockaddr*>(&query), &status);
    if (status != MMDB_SUCCESS || !result.found_entry) return {};

    constexpr const char* path[] = {"country", "iso_code", nullptr};
    MMDB_entry_data_s data{};
    status = MMDB_aget_value(&result.entry, &data, path);
    if (status != MMDB_SUCCESS || !data.has_data || data.type != MMDB_DATA_TYPE_UTF8_STRING ||
        data.data_size != 2)
        return {};
    const char* code = data.utf8_string;
    if (code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z') return {};
    return {code, 2};
}

static bool serve(int fd, u16 port, const MMDB_s& database) {
    sockaddr_in listener{};
    listener.sin_family = AF_INET;
    listener.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    listener.sin_port = htons(port);
    socklen_t listener_size = sizeof(listener);
    if (bind(fd, reinterpret_cast<const sockaddr*>(&listener), listener_size) < 0 ||
        getsockname(fd, reinterpret_cast<sockaddr*>(&listener), &listener_size) < 0) {
        perror("GeoIP listener");
        return false;
    }
    printf("Listening on 127.0.0.1:%u\n", static_cast<unsigned>(ntohs(listener.sin_port)));
    fflush(stdout);

    for (;;) {
        // An IPv4 string takes at most 15 bytes. A truncated datagram fills the
        // entire buffer and is rejected by parse_ipv4_address.
        char request[16];
        sockaddr_in peer{};
        socklen_t peer_size = sizeof(peer);
        const auto length = recvfrom(
            fd, request, sizeof(request), 0, reinterpret_cast<sockaddr*>(&peer), &peer_size);
        if (length < 0) {
            if (errno == EINTR) continue;
            perror("GeoIP receive");
            return false;
        }
        const auto result = country(database, {request, static_cast<u32>(length)});
        (void)sendto(fd,
                     result.ptr ? result.ptr : "",
                     result.len,
                     0,
                     reinterpret_cast<const sockaddr*>(&peer),
                     peer_size);
    }
}

int main(int argc, char** argv) {
    i64 port;
    range_int<0, 6> port_length;
    if (argc != 3 || !decltype(port_length)::try_from_u64(strnlen(argv[2], 6), &port_length) ||
        !parse_integer32({argv[2], port_length.to<u32>()}, &port) || port < 0 || port > 65535) {
        fprintf(stderr, "Usage: rut-geoip DATABASE.mmdb PORT\n");
        return 1;
    }
    MMDB_s database{};
    const int status = MMDB_open(argv[1], MMDB_MODE_MMAP, &database);
    if (status != MMDB_SUCCESS) {
        fprintf(stderr, "Failed to open GeoIP database %s: %s\n", argv[1], MMDB_strerror(status));
        return 1;
    }

    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("GeoIP socket");
        MMDB_close(&database);
        return 1;
    }
    const bool success = serve(fd, static_cast<u16>(port), database);
    close(fd);
    MMDB_close(&database);
    return success ? 0 : 1;
}
