// Standalone patch probe, not a production C++ ABI implementation.
#include "simdjson.h"
#ifdef SIMDJSON_THREADS_ENABLED
#error "allocator probe requires simdjson's non-threaded profile"
#endif
#include <cstdio>
#include <cstdlib>
#include <new>

namespace {
alignas(64) unsigned char storage[256 * 1024];
size_t used = 0;
unsigned calls = 0, active = 0, fail_at = 0;
}  // namespace
extern "C" void* simdjson_rut_allocate(size_t bytes, size_t alignment) noexcept {
    if (++calls == fail_at) return nullptr;
    size_t offset = (used + alignment - 1) & ~(alignment - 1);
    if (offset > sizeof(storage) || bytes > sizeof(storage) - offset) return nullptr;
    used = offset + bytes;
    ++active;
    return storage + offset;
}
extern "C" void simdjson_rut_deallocate(void* p) noexcept {
    if (p) --active;
}
// Retained upstream DOM paths need these symbols. Any use fails the probe:
// this deliberately does not hide ordinary allocations behind malloc/free.
namespace std {
const nothrow_t nothrow{};
void __throw_length_error(const char*) {
    abort();
}
void __throw_logic_error(const char*) {
    abort();
}
}  // namespace std
void* operator new(size_t) {
    abort();
}
void* operator new(size_t, const std::nothrow_t&) noexcept {
    abort();
}
void* operator new[](size_t, const std::nothrow_t&) noexcept {
    abort();
}
void operator delete(void*) noexcept {
    abort();
}
void operator delete(void*, size_t) noexcept {
    abort();
}
void operator delete[](void*) noexcept {
    abort();
}
extern "C" void __cxa_pure_virtual() {
    abort();
}

int main() {
    unsigned allocation_count = 0;
    {
        simdjson::ondemand::parser parser;
        if (parser.allocate(8192, 64)) return 1;
        allocation_count = calls;
        alignas(64) char input[128] = "{\"x\":42}";
        for (unsigned i = 0; i < 10000; ++i) {
            simdjson::ondemand::document doc;
            uint64_t value = 0;
            if (parser.iterate(input, 8, sizeof(input)).get(doc)) return 2;
            if (doc["x"].get_uint64().get(value) || value != 42) return 3;
        }
        if (calls != allocation_count) return 4;
    }
    if (active) return 5;
    for (unsigned failure = 1; failure <= allocation_count; ++failure) {
        used = calls = active = 0;
        fail_at = failure;
        {
            simdjson::ondemand::parser parser;
            auto error = parser.allocate(8192, 64);
            if (error != simdjson::MEMALLOC) {
                std::fprintf(stderr, "failure=%u error=%d calls=%u\n", failure, int(error), calls);
                return 6;
            }
            // Recovery on the same parser must work after allocation failure.
            fail_at = 0;
            if (parser.allocate(8192, 64)) return 7;
        }
        if (active) return 8;
    }
    std::printf("PASS: %u allocator failure points; 10000 parses without allocation\n",
                allocation_count);
}
