#pragma once

#include "rut/common/types.h"

namespace rut {

inline constexpr u32 kGeoIpCountryCodeLength = 2;

// The server owns one read-only mapping. Open before starting workers and
// destroy after all workers have joined.
class GeoIpDatabase {
public:
    GeoIpDatabase() = default;
    GeoIpDatabase(const GeoIpDatabase&) = delete;
    GeoIpDatabase& operator=(const GeoIpDatabase&) = delete;
    ~GeoIpDatabase();

    // Returns an error message on failure.
    const char* open(const char* path);

private:
    bool owns_mapping_ = false;
};

// Takes the network-order IPv4 representation used by Rut's IP type.
// Returns two bytes valid for the lifetime of the database, or nullptr.
const char* geoip_country(u32 address);

}  // namespace rut
