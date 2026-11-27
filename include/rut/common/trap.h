#pragma once

#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

namespace rut::detail {

[[gnu::cold, gnu::format(printf, 3, 0)]]
inline void log_fatal(const char* file, int line, const char* format, va_list args) noexcept {
    char message[1024]{};
    if (::vsnprintf(message, sizeof(message), format, args) < 0)
        ::snprintf(message, sizeof(message), "fatal diagnostic formatting failed");

    ::fprintf(stderr, "rut: %s:%d: %s\n", file, line, message);
    ::fflush(stderr);
    ::syslog(LOG_USER | LOG_CRIT, "rut: %s:%d: %s", file, line, message);
}

[[noreturn, gnu::cold, gnu::noinline, gnu::format(printf, 3, 4)]]
inline void log_and_trap(const char* file, int line, const char* format, ...) noexcept {
    va_list args;
    va_start(args, format);
    log_fatal(file, line, format, args);
    va_end(args);
    __builtin_trap();
}

}  // namespace rut::detail

#define RUT_TRAP(...) ::rut::detail::log_and_trap(__FILE__, __LINE__, __VA_ARGS__)
