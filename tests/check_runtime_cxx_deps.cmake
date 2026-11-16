# Check the shipped runtime, not the LLVM compiler or test executables.
execute_process(COMMAND "${READELF}" --wide --dynamic --dyn-syms "${RUT_BINARY}"
    RESULT_VARIABLE result OUTPUT_VARIABLE elf ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Cannot inspect runtime ELF: ${error}")
endif()
if(elf MATCHES "libstdc\\+\\+|libc\\+\\+|libc\\+\\+abi|libsupc\\+\\+|libabsl|libre2|libpcre|libLLVM|GLIBCXX_|CXXABI_")
    message(FATAL_ERROR "Rut imports a C++ runtime or shared compiler/regex backend:\n${elf}")
endif()
find_program(NM nm REQUIRED)
execute_process(COMMAND "${NM}" --undefined-only --demangle "${RUT_BINARY}"
    RESULT_VARIABLE nm_result OUTPUT_VARIABLE undefined_symbols ERROR_VARIABLE nm_error)
if(NOT nm_result EQUAL 0)
    message(FATAL_ERROR "Cannot inspect undefined runtime symbols: ${nm_error}")
endif()
if(undefined_symbols MATCHES " U (std::|absl::|operator new|operator delete|__cxa_throw|__gxx_personality)")
    message(FATAL_ERROR "Rut imports C++ runtime symbols:\n${undefined_symbols}")
endif()
