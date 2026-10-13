# Check the shipped runtime, not the LLVM compiler or test executables.
execute_process(COMMAND "${READELF}" --wide --dynamic --dyn-syms "${RUT_BINARY}"
    RESULT_VARIABLE result OUTPUT_VARIABLE elf ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Cannot inspect runtime ELF: ${error}")
endif()
if(elf MATCHES "libstdc\\+\\+|libc\\+\\+|libc\\+\\+abi|GLIBCXX_|CXXABI_")
    message(FATAL_ERROR "Rut imports a C++ standard library or ABI runtime:\n${elf}")
endif()
