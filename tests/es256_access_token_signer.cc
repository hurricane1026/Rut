#include "es256_fixture.h"
#include <cstdio>
#include <cstring>

int main() {
    rut::test::Es256Fixture fixture;
    if (!fixture.init() ||
        fwrite(fixture.policy.ptr, 1u, fixture.policy.len, stdout) != fixture.policy.len ||
        fputc('\n', stdout) == EOF || fflush(stdout) != 0)
        return 1;

    char line[8193];
    char token[16384];
    while (fgets(line, sizeof(line), stdin) != nullptr) {
        const size_t line_length = strlen(line);
        if (line_length < 2u || line[line_length - 1u] != '\n') return 2;
        line[line_length - 1u] = '\0';
        char* const separator = strchr(line, '\t');
        if (separator == nullptr) return 2;
        *separator = '\0';
        const rut::Str header{line, static_cast<rut::u32>(strlen(line))};
        const rut::Str claims{separator + 1u, static_cast<rut::u32>(strlen(separator + 1u))};
        if (header.len == 0u || header.len > 512u || claims.len == 0u || claims.len > 4096u)
            return 2;
        const rut::Str signed_token = fixture.sign(header, claims, token);
        if (signed_token.len == 0u || signed_token.len >= sizeof(token) ||
            fwrite(signed_token.ptr, 1u, signed_token.len, stdout) != signed_token.len ||
            fputc('\n', stdout) == EOF || fflush(stdout) != 0)
            return 3;
    }
    return ferror(stdin) ? 4 : 0;
}
