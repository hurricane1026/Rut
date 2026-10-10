#include "rut/compiler/hir.h"
#include "test.h"
#include <cstring>
#include <new>

#include <sys/mman.h>

using namespace rut;

TEST(hir_generated_names, releases_small_and_large_mapped_storage) {
    auto* names = static_cast<HirGeneratedNames*>(mmap(nullptr,
                                                       sizeof(HirGeneratedNames),
                                                       PROT_READ | PROT_WRITE,
                                                       MAP_PRIVATE | MAP_ANONYMOUS,
                                                       -1,
                                                       0));
    REQUIRE(names != MAP_FAILED);
    ::new (names) HirGeneratedNames{};
    names->mapped_owner = true;
    auto* small = static_cast<HirGeneratedName*>(mmap(nullptr,
                                                      sizeof(HirGeneratedName),
                                                      PROT_READ | PROT_WRITE,
                                                      MAP_PRIVATE | MAP_ANONYMOUS,
                                                      -1,
                                                      0));
    REQUIRE(small != MAP_FAILED);
    ::new (small) HirGeneratedName{};
    small->len = 512;
    small->text = static_cast<char*>(
        mmap(nullptr, small->len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    REQUIRE(small->text != MAP_FAILED);
    std::memset(small->text, 's', small->len);
    small->mapped = true;
    small->mapped_node = true;

    constexpr u32 kLargeLength = 8192;
    auto* large_text = static_cast<char*>(
        mmap(nullptr, kLargeLength, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    CHECK_NE(large_text, MAP_FAILED);
    std::memset(large_text, 'l', kLargeLength);
    auto* large = static_cast<HirGeneratedName*>(mmap(nullptr,
                                                      sizeof(HirGeneratedName),
                                                      PROT_READ | PROT_WRITE,
                                                      MAP_PRIVATE | MAP_ANONYMOUS,
                                                      -1,
                                                      0));
    CHECK_NE(large, MAP_FAILED);
    ::new (large) HirGeneratedName{};
    large->text = large_text;
    large->len = kLargeLength;
    large->mapped = true;
    large->mapped_node = true;
    small->next = large;
    names->head = small;
    names->release();
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
