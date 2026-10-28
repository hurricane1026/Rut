execute_process(COMMAND "${READELF}" --wide --program-headers --dynamic "${RUT_BINARY}"
    RESULT_VARIABLE result OUTPUT_VARIABLE elf ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Cannot inspect runtime ELF: ${error}")
endif()
if(elf MATCHES "(^|[\n\r])[ \t]*INTERP[ \t]" OR elf MATCHES "\\(NEEDED\\)")
    message(FATAL_ERROR "Runtime contains a dynamic interpreter or NEEDED entry:\n${elf}")
endif()
