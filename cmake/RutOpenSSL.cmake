# OpenSSL's C implementation keeps the native runtime free of C++ ABI imports.
# Do not discover a host installation: headers and archives must be one pinned
# release, and provider/config discovery must not depend on the host machine.
include(ExternalProject)
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()
find_package(Perl REQUIRED)
execute_process(
    COMMAND ${PERL_EXECUTABLE} -MFindBin -MFile::Compare -MFile::Copy -MIPC::Cmd -MTime::Piece -e 1
    RESULT_VARIABLE _rut_openssl_perl_status
    ERROR_VARIABLE _rut_openssl_perl_error
)
if(NOT _rut_openssl_perl_status EQUAL 0)
    message(FATAL_ERROR
        "OpenSSL requires Perl with its core modules (e.g. perl-core on Fedora). "
        "A private installation may be supplied with PERL5LIB.\n${_rut_openssl_perl_error}")
endif()
find_package(Threads REQUIRED)
find_program(RUT_OPENSSL_MAKE NAMES gmake make REQUIRED)

set(RUT_OPENSSL_BUILD_JOBS "4" CACHE STRING "Parallel jobs for the pinned OpenSSL build")
set(RUT_OPENSSL_TARGET "" CACHE STRING "OpenSSL Configure target (required when cross compiling)")
if(CMAKE_CROSSCOMPILING AND NOT RUT_OPENSSL_TARGET)
    message(FATAL_ERROR "Cross compiling requires an explicit RUT_OPENSSL_TARGET")
endif()

set(_rut_openssl_prefix "${CMAKE_CURRENT_BINARY_DIR}/third_party/openssl")
set(_rut_openssl_install "${_rut_openssl_prefix}/install")
# Imported include directories must exist at CMake generation time. The
# dependency below installs the actual headers before consumers are compiled.
file(MAKE_DIRECTORY "${_rut_openssl_install}/include")
string(TOUPPER "${CMAKE_BUILD_TYPE}" _rut_openssl_build_type)
set(_rut_openssl_cflags "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${_rut_openssl_build_type}}")

ExternalProject_Add(rut_openssl
    PREFIX "${_rut_openssl_prefix}"
    URL https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz
    URL_HASH SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env
        "CC=${CMAKE_C_COMPILER}" "AR=${CMAKE_AR}" "RANLIB=${CMAKE_RANLIB}"
        "CFLAGS=${_rut_openssl_cflags}"
        ${PERL_EXECUTABLE} <SOURCE_DIR>/Configure ${RUT_OPENSSL_TARGET}
        no-shared no-module no-dso no-autoload-config
        --prefix=${_rut_openssl_install} --libdir=lib
    BUILD_COMMAND ${RUT_OPENSSL_MAKE} -j${RUT_OPENSSL_BUILD_JOBS} build_libs
    INSTALL_COMMAND ${RUT_OPENSSL_MAKE} install_dev
    BUILD_BYPRODUCTS
        "${_rut_openssl_install}/lib/libssl.a"
        "${_rut_openssl_install}/lib/libcrypto.a"
    LOG_DOWNLOAD ON
    LOG_CONFIGURE ON
    LOG_BUILD ON
    LOG_INSTALL ON
)

add_library(crypto STATIC IMPORTED GLOBAL)
set_target_properties(crypto PROPERTIES
    IMPORTED_LOCATION "${_rut_openssl_install}/lib/libcrypto.a"
    INTERFACE_INCLUDE_DIRECTORIES "${_rut_openssl_install}/include"
    INTERFACE_LINK_LIBRARIES Threads::Threads
)
add_dependencies(crypto rut_openssl)
add_library(ssl STATIC IMPORTED GLOBAL)
set_target_properties(ssl PROPERTIES
    IMPORTED_LOCATION "${_rut_openssl_install}/lib/libssl.a"
    INTERFACE_INCLUDE_DIRECTORIES "${_rut_openssl_install}/include"
    INTERFACE_LINK_LIBRARIES crypto
)
add_dependencies(ssl rut_openssl)
