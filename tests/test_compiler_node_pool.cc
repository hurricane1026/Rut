#include "fault_injection.h"
#include "rut/compiler/hir.h"
#include "rut/compiler/lower_rir.h"
#include "rut/compiler/mir.h"
#include "rut/compiler/mir_build.h"
#include "test.h"

using namespace rut;
using rut::test_fault::ScopedMemoryFault;

TEST(node_pool, growth_keeps_addresses_and_reports_allocation_failure) {
    NodePool<u64> pool;
    REQUIRE(pool.push(42));
    auto* first = &pool[0];
    for (u32 i = 1; i < 4096; ++i) REQUIRE(pool.push(i));
    CHECK(first == &pool[0]);
    CHECK(*first == 42);
    for (u32 i = 0; i < pool.len; ++i) CHECK(pool.index_of(&pool[i]) == i);
    u64 outside = 0;
    CHECK(pool.index_of(&outside) == 0xffffffffu);
    CHECK(pool.index_of(nullptr) == 0xffffffffu);
    {
        // Chunks already allocated remain readable after a failed extension.
        ScopedMemoryFault fault(1);
        bool failed = false;
        for (u32 i = 0; i < 4096; ++i) {
            if (!pool.push(i)) {
                failed = true;
                break;
            }
        }
        CHECK(failed);
        CHECK(!pool.ok());
        CHECK(!pool.push(0));
        CHECK(*first == 42);
    }
    NodePool<u64> empty;
    {
        ScopedMemoryFault fault(1);
        CHECK(!empty.push(1));
    }
    CHECK(!empty.ok());
    CHECK(empty.len == 0);
}

TEST(node_pool, copy_failure_is_explicit_and_assignment_can_replace_invalid_storage) {
    NodePool<u64> source;
    for (u32 i = 0; i < 1024; ++i) REQUIRE(source.push(i));
    {
        ScopedMemoryFault fault(1);
        NodePool<u64> failed(source);
        CHECK(!failed.ok());
        CHECK(failed.len == 0);
        CHECK(source.ok());
    }
    {
        ScopedMemoryFault fault(2);
        NodePool<u64> partial(source);
        CHECK(!partial.ok());
        CHECK(partial.len > 0);
        CHECK(partial.len < source.len);
        for (u32 i = 0; i < partial.len; ++i) CHECK(partial[i] == i);
    }
    NodePool<u64> assigned;
    {
        ScopedMemoryFault fault(1);
        assigned = source;
        CHECK(!assigned.ok());
    }
    assigned = source;
    REQUIRE(assigned.ok());
    CHECK(assigned.len == source.len);
    assigned[1000] = 7;
    CHECK(source[1000] == 1000);
}

TEST(node_pool, hir_and_mir_copies_rebase_pointers_across_chunks) {
    HirRoute route;
    MirFunction function;
    HirFunction helper;
    for (u32 i = 0; i < 1024; ++i) {
        HirExpr expr{};
        expr.kind = HirExprKind::IntLit;
        expr.int_value = i;
        if (i != 0) expr.lhs = &route.exprs[i - 1];
        REQUIRE(route.exprs.push(expr));
        expr.lhs = i == 0 ? nullptr : &helper.exprs[i - 1];
        REQUIRE(helper.exprs.push(expr));
        MirValue value{};
        value.kind = MirValueKind::IntConst;
        value.int_value = i;
        if (i != 0) value.lhs = &function.values[i - 1];
        REQUIRE(function.values.push(value));
    }
    HirRoute route_copy(route);
    HirFunction helper_copy(helper);
    MirFunction function_copy(function);
    REQUIRE(route_copy.exprs.ok());
    REQUIRE(helper_copy.exprs.ok());
    REQUIRE(function_copy.values.ok());
    for (u32 i = 1; i < 1024; ++i) {
        CHECK(route_copy.exprs[i].lhs == &route_copy.exprs[i - 1]);
        CHECK(helper_copy.exprs[i].lhs == &helper_copy.exprs[i - 1]);
        CHECK(function_copy.values[i].lhs == &function_copy.values[i - 1]);
    }
    route_copy.exprs[0].int_value = 99;
    CHECK(route.exprs[0].int_value == 0);
    // Exercise assignment and the existing owner move/rebase paths too.
    route = static_cast<HirRoute&&>(route_copy);
    helper = static_cast<HirFunction&&>(helper_copy);
    function = static_cast<MirFunction&&>(function_copy);
    for (u32 i = 1; i < 1024; ++i) {
        CHECK(route.exprs[i].lhs == &route.exprs[i - 1]);
        CHECK(helper.exprs[i].lhs == &helper.exprs[i - 1]);
        CHECK(function.values[i].lhs == &function.values[i - 1]);
    }
}

TEST(node_pool, pipeline_rejects_failed_owner_storage_as_out_of_memory) {
    MmapArena storage;
    REQUIRE(storage.init(4096));
    auto* hir = storage.alloc_t<HirModule>();
    auto* mir = storage.alloc_t<MirModule>();
    REQUIRE(hir != nullptr);
    REQUIRE(mir != nullptr);
    hir->routes.len = 1;
    mir->functions.len = 1;
    {
        ScopedMemoryFault fault(1);
        CHECK(!hir->routes[0].exprs.push(HirExpr{}));
    }
    {
        ScopedMemoryFault fault(1);
        CHECK(!mir->functions[0].values.push(MirValue{}));
    }
    auto built = build_mir(*hir);
    CHECK(!built);
    if (!built) CHECK(built.error().code == FrontendError::OutOfMemory);
    FrontendRirModule rir{};
    auto lowered = lower_to_rir(*mir, rir);
    CHECK(!lowered);
    if (!lowered) CHECK(lowered.error().code == FrontendError::OutOfMemory);
    rir.destroy();
    mir->~MirModule();
    hir->~HirModule();
    storage.destroy();
}

int main(int argc, char** argv) {
    return rut::test::run_all(argc, argv);
}
