include("${CMAKE_CURRENT_LIST_DIR}/../cmake/RutOpenSSLCompiler.cmake")

set(test_dir "${CMAKE_CURRENT_BINARY_DIR}/openssl compiler argv test")
file(REMOVE_RECURSE "${test_dir}")
file(MAKE_DIRECTORY "${test_dir}")
set(fake_compiler "${test_dir}/fake compiler")
set(argv_capture "${test_dir}/argv.txt")
file(WRITE "${fake_compiler}" "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$RUT_ARGV_CAPTURE\"\n")
file(CHMOD "${fake_compiler}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)

# This command is shaped like an OpenSSL Makefile recipe: Configure stores the
# CC/CFLAGS strings in the generated Makefile, whose shell parses them at build
# time. Capture argv to verify quoting survives that boundary.
rut_openssl_compiler_environment(cc cflags
    "${fake_compiler}" "--wrapper-option='arg with spaces'"
    "aarch64-linux-musl" "/opt/sdk root"
    "-O2 -DOPENSSL_TEST=1")
execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "RUT_ARGV_CAPTURE=${argv_capture}"
        /bin/sh -c "${cc} ${cflags} -c"
    RESULT_VARIABLE command_result
    ERROR_VARIABLE command_error
)
if(NOT command_result EQUAL 0)
    message(FATAL_ERROR "fake OpenSSL compiler invocation failed: ${command_error}")
endif()
file(READ "${argv_capture}" captured_argv)
set(expected_argv
    "--wrapper-option=arg with spaces\n-O2\n-DOPENSSL_TEST=1\n--target=aarch64-linux-musl\n--sysroot=/opt/sdk root\n-c\n")
if(NOT captured_argv STREQUAL expected_argv)
    message(FATAL_ERROR "unexpected OpenSSL compiler argv:\n${captured_argv}")
endif()

# Native builds must not receive empty target/sysroot switches.
rut_openssl_compiler_environment(native_cc native_flags
    "/usr/bin/cc" "" "" "" "-O0")
if(NOT native_cc STREQUAL "'/usr/bin/cc'" OR NOT native_flags STREQUAL "-O0")
    message(FATAL_ERROR "native OpenSSL compiler environment changed: '${native_cc}' '${native_flags}'")
endif()

file(REMOVE_RECURSE "${test_dir}")
