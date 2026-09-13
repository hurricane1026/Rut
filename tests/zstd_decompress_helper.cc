#include <unistd.h>
#include <zstd.h>

int main() {
    char compressed[8192];
    size_t compressed_size = 0u;
    while (compressed_size < sizeof(compressed)) {
        const ssize_t count =
            read(STDIN_FILENO, compressed + compressed_size, sizeof(compressed) - compressed_size);
        if (count < 0) return 1;
        if (count == 0) break;
        compressed_size += static_cast<size_t>(count);
    }
    if (compressed_size == 0u || compressed_size == sizeof(compressed)) return 1;

    char plain[8192];
    const size_t plain_size = ZSTD_decompress(plain, sizeof(plain), compressed, compressed_size);
    if (ZSTD_isError(plain_size)) return 1;
    size_t written = 0u;
    while (written < plain_size) {
        const ssize_t count = write(STDOUT_FILENO, plain + written, plain_size - written);
        if (count <= 0) return 1;
        written += static_cast<size_t>(count);
    }
    return 0;
}
