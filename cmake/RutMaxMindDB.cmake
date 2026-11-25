include(FetchContent)
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()

function(rut_add_maxminddb)
    set(BUILD_SHARED_LIBS OFF)
    set(BUILD_TESTING OFF)
    set(BUILD_FUZZING OFF)
    set(MAXMINDDB_BUILD_BINARIES OFF)
    set(MAXMINDDB_INSTALL OFF)
    FetchContent_Declare(rut_maxminddb
        URL https://github.com/maxmind/libmaxminddb/releases/download/1.14.1/libmaxminddb-1.14.1.tar.gz
        URL_HASH SHA256=ca5c87d41339f8bc4daabb53e8a9356b3c995f2d2419b85d7bff823b2ecc252d)
    FetchContent_MakeAvailable(rut_maxminddb)
endfunction()

rut_add_maxminddb()
