#include "concurrency_reference.h"
#include "rut/compiler/analyze.h"
#include "rut/compiler/lexer.h"
#include "rut/compiler/lower_rir.h"
#include "rut/compiler/mir_build.h"
#include "rut/compiler/parser.h"
#include "rut/compiler/verifier.h"
#include "test.h"

#include <stdio.h>
#include <string.h>

using namespace rut;
using namespace rut::rir;

namespace {

struct Case {
    const char* name;
    const char* source;
    verify::Issue expected;
    VerifyIssueCode compiler_issue;
};
constexpr Case kCases[] = {
    {"receive_first",
     "deadlock/receive-before-send.rut",
     verify::Issue::Deadlock,
     VerifyIssueCode::HandlerDeadlock},
    {"send_first", "deadlock/send-before-receive.rut", verify::Issue::None, VerifyIssueCode::None},
    {"any_timeout", "verification/timer-race.rut", verify::Issue::None, VerifyIssueCode::None},
    {"any_blocked",
     "verification/timer-race.rut",
     verify::Issue::Deadlock,
     VerifyIssueCode::HandlerDeadlock},
    {"ownership",
     "verification/timer-race.rut",
     verify::Issue::UnsafeAction,
     VerifyIssueCode::ConcurrentProtocolFailure},
    {"resource_leak",
     "verification/timer-race.rut",
     verify::Issue::ResourceLeak,
     VerifyIssueCode::ConcurrentProtocolFailure},
    {"sleep", "verification/sleep.rut", verify::Issue::None, VerifyIssueCode::None},
    {"yield_cycle",
     "verification/sleep.rut",
     verify::Issue::Livelock,
     VerifyIssueCode::HandlerLivelock},
};

// All source/contract storage stays alive through checking and serialization.
struct Fixture {
    char source[4096]{};
    AstFile* ast = nullptr;
    HirModule* hir = nullptr;
    MirModule* mir = nullptr;
    FrontendRirModule rir{};
    VerifyHandlerAutomaton automaton{};
    VerifyPeerBinding bindings[3]{};
    verify::Action actions[2]{};
    verify::Model peer{};
    VerifyPeerEnvironment environment{};
    VerifyHandlerProtocolModel protocol{};
    VerifyResult compiler_result{};
    u32 root = 0;

    ~Fixture() {
        rir.destroy();
        delete mir;
        delete hir;
        delete ast;
    }

    bool prepare(const Case& test_case) {
        char path[1024];
        const int length =
            snprintf(path, sizeof(path), "%s/tests/fixtures/%s", RUT_SOURCE_DIR, test_case.source);
        if (length < 0 || static_cast<u32>(length) >= sizeof(path)) return false;
        FILE* file = fopen(path, "rb");
        if (!file) return false;
        const u32 size = static_cast<u32>(fread(source, 1, sizeof(source), file));
        const bool valid = !ferror(file) && size < sizeof(source);
        fclose(file);
        if (!valid) return false;
        auto lexed = lex({source, size});
        if (!lexed) return false;
        auto parsed = parse_file(lexed.value());
        if (!parsed) return false;
        ast = parsed.value();
        auto analyzed = analyze_file(*ast);
        if (!analyzed) return false;
        hir = analyzed.value();
        auto lowered = build_mir(*hir);
        if (!lowered) return false;
        mir = lowered.value();
        if (!lower_to_rir(*mir, rir) || rir.module.func_count != 1) return false;
        auto& fn = rir.module.functions[0];
        // Verify real lowered RIR before composing, including the codegen root.
        if (!verify_function(&fn).ok) return false;
        root = fn.has_explicit_resume_blocks ? fn.resume_blocks[0]
               : fn.state_zero_enters_entry  ? fn.state_zero_entry_block
                                             : fn.blocks[0].id.id;
        if (!strcmp(test_case.name, "yield_cycle")) {
            const u32 resume =
                fn.has_explicit_resume_blocks ? fn.resume_blocks[1] : fn.resume_terminal_block;
            auto& block = fn.blocks[resume];
            auto& terminator = block.insts[block.inst_count - 1];
            terminator = {};
            terminator.op = Opcode::Jmp;
            terminator.imm.block_targets[0] = BlockId{root};
        }
        if (!build_verify_handler_automaton(&fn, automaton)) return false;
        const bool sleep = !strcmp(test_case.source, "verification/sleep.rut");
        const bool exchange = !strncmp(test_case.source, "deadlock/", 9);
        VerifyOptions options{};
        if (!sleep) {
            peer.actor_count = 1;
            peer.actions = actions;
            environment.model = &peer;
            environment.bindings = bindings;
            for (u32 i = 0; i < automaton.node_count; ++i) {
                const auto& node = automaton.nodes[i];
                if (node.kind != VerifyHandlerNodeKind::Yield) continue;
                if (environment.binding_count == 3) return false;
                auto& binding = bindings[environment.binding_count++];
                binding.block_index = i;
                if (exchange) {
                    if (node.wait_arm_mask == kWaitEventArmUpstreamSend)
                        binding.submit_set = 1;
                    else if (node.wait_arm_mask == kWaitEventArmUpstreamRecv) {
                        binding.completion_set = 2;
                        binding.completion_clear = 2;
                    } else if (node.wait_arm_mask != kWaitEventArmUpstreamConnect)
                        return false;
                } else {
                    binding.submit_set = 4;
                    binding.arm_count = 2;
                    binding.arms[0] = {kWaitEventArmRecv, 1, 1};
                    binding.arms[1] = {kWaitEventArmTimer, 2, 2};
                    if (!strcmp(test_case.name, "any_blocked")) binding.arms[1].completion_set = 8;
                    if (!strcmp(test_case.name, "ownership")) binding.submit_require_set = 16;
                }
            }
            actions[0].to = 1;
            actions[0].guard_set = exchange ? 1 : 4;
            actions[0].clear = actions[0].guard_set;
            actions[0].set = 2;
            peer.actors[0] = {
                static_cast<u16>(exchange ? 3 : 2), 0, static_cast<u16>(exchange ? 2 : 1)};
            peer.action_count = exchange ? 2 : 1;
            peer.terminal_clear = exchange ? 3 : 6;
            if (exchange) {
                actions[1].from = 1;
                actions[1].to = 2;
                actions[1].guard_clear = 2;
            }
            if (!strcmp(test_case.name, "resource_leak")) {
                actions[0].set |= 32;
                peer.terminal_clear |= 32;
            }
            options.environment = &environment;
        }
        compiler_result = verify_function(&fn, 0, options);
        return build_handler_protocol_model(automaton, root, options.environment, protocol).ok;
    }
};

TEST(HandlerReference, ActualLoweredSourceAgreesWithCompilerAdmission) {
    for (const auto& test_case : kCases) {
        Fixture fixture;
        REQUIRE(fixture.prepare(test_case));
        CHECK_EQ(fixture.compiler_result.issue.code, test_case.compiler_issue);
        CHECK_EQ(fixture.compiler_result.ok, test_case.expected == verify::Issue::None);
        const auto checked = verify::check(fixture.protocol.model);
        CHECK_EQ(checked.issue, test_case.expected);
        if (!checked.ok) CHECK(checked.trace_count > 0);
    }
}

TEST(HandlerReference, FailedRebuildClearsPreviouslyExportableModel) {
    Fixture fixture;
    REQUIRE(fixture.prepare(kCases[1]));
    REQUIRE(fixture.protocol.model.actor_count == 2);
    auto& binding = fixture.bindings[0];
    binding.block_index = fixture.automaton.node_count;
    CHECK_FALSE(build_handler_protocol_model(
                    fixture.automaton, fixture.root, &fixture.environment, fixture.protocol)
                    .ok);
    CHECK_EQ(fixture.protocol.model.actor_count, 0u);
    CHECK(fixture.protocol.model.actions == nullptr);
    CHECK_EQ(verify::check(fixture.protocol.model).issue, verify::Issue::InvalidModel);
}

int export_case(const char* name) {
    for (const auto& test_case : kCases) {
        if (strcmp(name, test_case.name)) continue;
        Fixture fixture;
        if (!fixture.prepare(test_case) ||
            fixture.compiler_result.issue.code != test_case.compiler_issue)
            return 1;
        const auto checked = verify::check(fixture.protocol.model);
        if (checked.issue != test_case.expected) return 1;
        printf("\\* source-fixture: %s\n", test_case.source);
        return rut::test::export_concurrency_reference(fixture.protocol.model);
    }
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    constexpr char kExport[] = "--export-reference=";
    if (argc == 2 && !strncmp(argv[1], kExport, sizeof(kExport) - 1))
        return export_case(argv[1] + sizeof(kExport) - 1);
    return rut::test::run_all(argc, argv);
}
