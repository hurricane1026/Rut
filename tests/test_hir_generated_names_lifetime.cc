#include "rut/compiler/hir.h"
#include "test.h"
#include <cstring>
#include <new>

#include <sys/mman.h>

using namespace rut;

TEST(hir_generated_names, arena_owns_many_generated_names_until_final_release) {
    auto* names = static_cast<HirGeneratedNames*>(mmap(nullptr,
                                                       sizeof(HirGeneratedNames),
                                                       PROT_READ | PROT_WRITE,
                                                       MAP_PRIVATE | MAP_ANONYMOUS,
                                                       -1,
                                                       0));
    REQUIRE(names != MAP_FAILED);
    ::new (names) HirGeneratedNames{};
    REQUIRE(names->arena.init(4096));

    char* first = nullptr;
    for (u32 i = 0; i < 512; i++) {
        auto* node = names->arena.alloc_t<HirGeneratedName>();
        REQUIRE(node != nullptr);
        node->text = static_cast<char*>(names->arena.alloc(12));
        REQUIRE(node->text != nullptr);
        std::memset(node->text, 'a' + (i % 26), 12);
        node->len = 12;
        node->next = names->head;
        names->head = node;
        first = node->text;
    }
    names->retain();
    names->release();
    CHECK_EQ(first[0], 'a' + (511 % 26));
    CHECK_NE(names->head, nullptr);
    names->release();
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
