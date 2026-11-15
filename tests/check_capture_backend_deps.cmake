# Upstream RE2/Abseil is statically built; its C++ runtime is the only accepted
# change to the server dependency policy. No LLVM or shared regex engines.
execute_process(COMMAND "${READELF}" --wide --dynamic --dyn-syms "${RUT_BINARY}"
    RESULT_VARIABLE result OUTPUT_VARIABLE elf ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Cannot inspect runtime ELF: ${error}")
endif()
if(elf MATCHES "Shared library: [[][^]]*(LLVM|llvm|libre2|libabsl|libpcre)[^]]*[]]")
    message(FATAL_ERROR "Rut imports LLVM or a shared regex backend:\n${elf}")
endif()
