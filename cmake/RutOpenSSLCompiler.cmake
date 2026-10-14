# OpenSSL's Configure/build invokes CC directly rather than through CMake, so
# reproduce the compiler arguments CMake normally supplies for cross builds.
# Configure stores CC and CFLAGS as command fragments in its generated
# Makefile; quote individual arguments for the recipe shell at that boundary.
function(rut_openssl_shell_quote out value)
    string(REPLACE "'" "'\\''" _quoted "${value}")
    set(${out} "'${_quoted}'" PARENT_SCOPE)
endfunction()

function(rut_openssl_compiler_environment out_cc out_cflags compiler compiler_arg1
         compiler_target sysroot base_cflags)
    rut_openssl_shell_quote(_cc "${compiler}")
    if(NOT "${compiler_arg1}" STREQUAL "")
        separate_arguments(_compiler_args NATIVE_COMMAND "${compiler_arg1}")
        foreach(_arg IN LISTS _compiler_args)
            rut_openssl_shell_quote(_quoted_arg "${_arg}")
            string(APPEND _cc " ${_quoted_arg}")
        endforeach()
    endif()

    set(_cflags "${base_cflags}")
    if(NOT "${compiler_target}" STREQUAL "")
        rut_openssl_shell_quote(_target_flag "--target=${compiler_target}")
        string(APPEND _cflags " ${_target_flag}")
    endif()
    if(NOT "${sysroot}" STREQUAL "")
        rut_openssl_shell_quote(_sysroot_flag "--sysroot=${sysroot}")
        string(APPEND _cflags " ${_sysroot_flag}")
    endif()
    set(${out_cc} "${_cc}" PARENT_SCOPE)
    set(${out_cflags} "${_cflags}" PARENT_SCOPE)
endfunction()
