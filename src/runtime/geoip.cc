#include "rut/runtime/geoip.h"

#include <maxminddb.h>
#include <netinet/in.h>

namespace rut {
namespace {

MMDB_s database{};
bool database_open = false;

}  // namespace

const char* GeoIpDatabase::open(const char* path) {
    if (database_open) return "a GeoIP database is already open";
    const int status = MMDB_open(path, MMDB_MODE_MMAP, &database);
    if (status != MMDB_SUCCESS) return MMDB_strerror(status);
    database_open = true;
    owns_mapping_ = true;
    return nullptr;
}

GeoIpDatabase::~GeoIpDatabase() {
    if (owns_mapping_) {
        MMDB_close(&database);
        database_open = false;
    }
}

const char* geoip_country(u32 address) {
    if (!database_open) return nullptr;

    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_addr.s_addr = address;
    int status = MMDB_SUCCESS;
    auto result =
        MMDB_lookup_sockaddr(&database, reinterpret_cast<const sockaddr*>(&peer), &status);
    if (status != MMDB_SUCCESS || !result.found_entry) return nullptr;

    const char* const path[] = {"country", "iso_code", nullptr};
    MMDB_entry_data_s data{};
    status = MMDB_aget_value(&result.entry, &data, path);
    if (status != MMDB_SUCCESS || !data.has_data || data.type != MMDB_DATA_TYPE_UTF8_STRING ||
        data.data_size != kGeoIpCountryCodeLength)
        return nullptr;

    const char* code = data.utf8_string;
    if (code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z') return nullptr;
    return code;
}

}  // namespace rut
