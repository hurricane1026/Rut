#include "fixture_privileged_listener.h"
#include <cerrno>
#include <cstdio>
#include <limits>
#include <string>
#include <vector>

namespace listener = rut::test::fixture_privileged_listener;

namespace {

constexpr listener::ListenerPlan kPlan{0x0a010203u, 0x0a010204u, 8080u};
constexpr char kHeader[] =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  "
    "timeout inode\n";

bool check(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "FAIL: %s\n", message);
    return condition;
}

std::string row(const std::string& endpoint,
                const std::string& state,
                const std::string& inode,
                unsigned slot = 0u) {
    return " " + std::to_string(slot) + ": " + endpoint + " 00000000:0000 " + state +
           " 00000000:00000000 00:00000000 00000000 1000 0 " + inode +
           " 1 0000000000000000 100 0 0 10 0\n";
}

bool plan_and_source_tests() {
    listener::Diagnostic diagnostic;
    listener::ListenerPlanText text;
    bool ok =
        check(listener::validate_listener_plan(kPlan, text, diagnostic) &&
                  text.positive_ipv4 == "10.1.2.3" && text.guard_ipv4 == "10.1.2.4" &&
                  text.positive_endpoint == "10.1.2.3:8080" &&
                  text.guard_endpoint == "10.1.2.4:8080" && text.wildcard_endpoint == ":8080" &&
                  diagnostic.phase == listener::DiagnosticPhase::None,
              "canonical listener plan was not validated/formatted exactly");
    auto rejected = [&](listener::ListenerPlan mutation, const char* message) {
        listener::ListenerPlanText ignored;
        listener::Diagnostic failure;
        ok = check(!listener::validate_listener_plan(mutation, ignored, failure) &&
                       failure.phase == listener::DiagnosticPhase::Plan,
                   message) &&
             ok;
    };
    listener::ListenerPlan mutation = kPlan;
    mutation.positive_ipv4 = 0u;
    rejected(mutation, "wildcard positive address was accepted");
    mutation = kPlan;
    mutation.guard_ipv4 = 0u;
    rejected(mutation, "wildcard guard address was accepted");
    mutation = kPlan;
    mutation.guard_ipv4 = mutation.positive_ipv4;
    rejected(mutation, "equal positive and guard addresses were accepted");
    mutation = kPlan;
    mutation.positive_ipv4 = 0x7f000001u;
    rejected(mutation, "loopback positive address was accepted");
    mutation = kPlan;
    mutation.guard_ipv4 = 0x7fffffffu;
    rejected(mutation, "loopback guard address was accepted");
    mutation = kPlan;
    mutation.port = 0u;
    rejected(mutation, "zero selected port was accepted");
    mutation = kPlan;
    mutation.port = 65536u;
    rejected(mutation, "one-past-maximum selected port was accepted");
    mutation = kPlan;
    mutation.port = 0xffffffffu;
    rejected(mutation, "large selected port was narrowed and accepted");
    mutation = kPlan;
    mutation.port = std::numeric_limits<std::uint64_t>::max();
    rejected(mutation, "maximum-width selected port was narrowed and accepted");

    mutation = kPlan;
    mutation.port = 65535u;
    ok = check(listener::validate_listener_plan(mutation, text, diagnostic) &&
                   text.positive_endpoint == "10.1.2.3:65535" && text.wildcard_endpoint == ":65535",
               "maximum selected port was not formatted canonically") &&
         ok;

    std::string source;
    static constexpr char kExact[] =
        "listen 10.1.2.3:8080\n"
        "route exact slash_normalized GET \"/\" { return local_response({ status: 204 }) }\n";
    static constexpr char kWildcard[] =
        "listen :8080\n"
        "route exact slash_normalized GET \"/\" { return local_response({ status: 204 }) }\n";
    ok = check(listener::build_listener_source(
                   kPlan, listener::ListenerSourceKind::Exact, source, diagnostic) &&
                   source == kExact,
               "exact one-shard ordinary-RUT source was not byte-exact") &&
         ok;
    ok = check(listener::build_listener_source(
                   kPlan, listener::ListenerSourceKind::Wildcard, source, diagnostic) &&
                   source == kWildcard,
               "wildcard one-shard ordinary-RUT source was not byte-exact") &&
         ok;
    source = "unchanged";
    ok = check(!listener::build_listener_source(
                   kPlan, static_cast<listener::ListenerSourceKind>(255u), source, diagnostic) &&
                   source.empty() && diagnostic.phase == listener::DiagnosticPhase::Source,
               "unknown listener source kind was silently approximated") &&
         ok;
    source = "stale";
    mutation = kPlan;
    mutation.port = 0u;
    ok = check(!listener::build_listener_source(
                   mutation, listener::ListenerSourceKind::Exact, source, diagnostic) &&
                   source.empty() && diagnostic.phase == listener::DiagnosticPhase::Plan,
               "invalid plan source construction did not fail before output") &&
         ok;
    return ok;
}

bool proc_parser_tests() {
    const std::string valid = std::string(kHeader) + row("0302010A:1F90", "0A", "111") +
                              row("0402010A:1F90", "07", "222", 1u) +
                              row("00000000:1F91", "0A", "333", 2u);
    listener::ProcTcpTable table;
    listener::Diagnostic diagnostic;
    bool ok = check(listener::parse_proc_net_tcp(valid, table, diagnostic) && table.count == 3u &&
                        table.rows[0].local_ipv4 == kPlan.positive_ipv4 &&
                        table.rows[0].local_port == kPlan.port && table.rows[0].state == 0x0au &&
                        table.rows[0].inode == 111u &&
                        table.rows[1].local_ipv4 == kPlan.guard_ipv4 && diagnostic.row_count == 3u,
                    "bounded proc tcp parser did not preserve needed fields");
    auto rejects = [&](const std::string& value, const char* message) {
        listener::ProcTcpTable ignored;
        listener::Diagnostic failure;
        ok = check(!listener::parse_proc_net_tcp(value, ignored, failure) &&
                       (failure.phase == listener::DiagnosticPhase::ProcHeader ||
                        failure.phase == listener::DiagnosticPhase::ProcRow),
                   message) &&
             ok;
    };
    rejects("bad header\n" + row("0302010A:1F90", "0A", "111"),
            "malformed proc header was accepted");
    rejects(valid.substr(0u, valid.size() - 1u), "truncated proc input was accepted");
    std::string embedded_nul = valid;
    embedded_nul[embedded_nul.find("111")] = '\0';
    rejects(embedded_nul, "embedded NUL proc input was accepted");
    rejects(std::string(listener::kMaxProcBytes + 1u, 'x') + "\n",
            "over-bound proc input was accepted");
    rejects(std::string(kHeader) + row("0302010:1F90", "0A", "111"),
            "short local IPv4 field was accepted");
    rejects(std::string(kHeader) + row("0302010Z:1F90", "0A", "111"),
            "non-hex local IPv4 field was accepted");
    rejects(std::string(kHeader) + row("0302010A:10000", "0A", "111"),
            "overflow local port was accepted");
    rejects(std::string(kHeader) + row("0302010A:1F90", "A", "111"),
            "short TCP state was accepted");
    rejects(std::string(kHeader) + row("0302010A:1F90", "0Z", "111"),
            "non-hex TCP state was accepted");
    rejects(std::string(kHeader) + row("0302010A:1F90", "0A", "inode"),
            "non-decimal inode was accepted");
    rejects(std::string(kHeader) + row("0302010A:1F90", "0A", "18446744073709551616"),
            "overflow inode was accepted");
    std::string bad_remote = std::string(kHeader) + row("0302010A:1F90", "0A", "111");
    bad_remote.replace(bad_remote.find("00000000:0000"), 13u, "not-an-endpt!");
    rejects(bad_remote, "malformed remote endpoint was accepted");
    rejects(std::string(kHeader) + " 0: 0302010A:1F90 00000000:0000 0A\n",
            "short proc row was accepted");
    rejects(std::string(kHeader) + "\n", "blank proc row was accepted");
    rejects(std::string(kHeader) + row("0302010A:1F90", "0A", "111") +
                row("0302010A:1F90", "0A", "111", 1u),
            "duplicate proc record was accepted");
    rejects(std::string(kHeader) + row("0302010A:1F90", "0A", "111") +
                row("00000000:1F91", "0A", "111", 1u),
            "same socket inode reused by another proc record was accepted");
    std::string over_rows = kHeader;
    for (std::size_t i = 0u; i <= listener::kMaxProcRows; ++i)
        over_rows += row("0302010A:1F90", "07", std::to_string(1000u + i), i);
    rejects(over_rows, "over-bound proc row count was accepted");
    return ok;
}

bool guard_reservation_tests() {
    listener::Diagnostic diagnostic;
    listener::ProcTcpTable table;
    listener::GuardReservationEvidence evidence;
    const std::string exact = std::string(kHeader) + row("00000000:1F91", "0A", "333");
    bool ok =
        check(listener::parse_proc_net_tcp(exact, table, diagnostic) &&
                  listener::classify_guard_reservation(table, kPlan, 222u, evidence, diagnostic) &&
                  evidence.target_owned_inode == 222u &&
                  diagnostic.phase == listener::DiagnosticPhase::None,
              "exact target-owned guard reservation was not classified");
    auto rejected = [&](const std::string& contents, std::uint64_t inode, const char* message) {
        listener::ProcTcpTable mutation;
        listener::Diagnostic failure;
        listener::GuardReservationEvidence ignored;
        ok = check(listener::parse_proc_net_tcp(contents, mutation, failure) &&
                       !listener::classify_guard_reservation(
                           mutation, kPlan, inode, ignored, failure) &&
                       failure.phase != listener::DiagnosticPhase::None,
                   message) &&
             ok;
    };
    rejected(std::string(kHeader) + row("0402010A:1F90", "0A", "222"),
             222u,
             "selected-port listener was accepted beside a guard reservation");
    rejected(std::string(kHeader) + row("0302010A:1F90", "07", "222"),
             222u,
             "selected-port TCP_CLOSE record was accepted beside a guard reservation");
    rejected(std::string(kHeader) + row("0402010A:1F90", "07", "223"),
             222u,
             "unpublished selected-port record was accepted beside a guard reservation");
    listener::GuardReservationEvidence ignored;
    listener::Diagnostic failure;
    ok = check(!listener::classify_guard_reservation(table, kPlan, 0u, ignored, failure) &&
                   failure.phase == listener::DiagnosticPhase::Ownership,
               "zero target-owned guard inode was accepted") &&
         ok;
    return ok;
}

bool evidence_tests() {
    listener::Diagnostic diagnostic;
    listener::ProcTcpTable exact;
    const std::string exact_text = std::string(kHeader) + row("0302010A:1F90", "0A", "111") +
                                   row("0402010A:1F90", "07", "222", 1u) +
                                   row("00000000:1F91", "0A", "333", 2u);
    bool ok = check(listener::parse_proc_net_tcp(exact_text, exact, diagnostic),
                    "exact evidence table setup failed");
    listener::ListenerEvidence evidence;
    ok = check(listener::classify_listener_evidence(exact,
                                                    kPlan,
                                                    {111u},
                                                    listener::ListenerEvidenceKind::ExactPositive,
                                                    evidence,
                                                    diagnostic) &&
                   evidence.kind == listener::ListenerEvidenceKind::ExactPositive &&
                   !evidence.guard_covered_by_listener && evidence.child_owned_inode == 111u &&
                   diagnostic.match_count == 1u && diagnostic.owned_count == 1u,
               "exact positive child-owned listener was not classified") &&
         ok;
    auto rejects = [&](const listener::ProcTcpTable& table,
                       const std::vector<std::uint64_t>& owned,
                       listener::ListenerEvidenceKind expected,
                       listener::DiagnosticPhase phase,
                       const char* message) {
        listener::ListenerEvidence ignored;
        listener::Diagnostic failure;
        ok = check(!listener::classify_listener_evidence(
                       table, kPlan, owned, expected, ignored, failure) &&
                       failure.phase == phase,
                   message) &&
             ok;
    };
    rejects(exact,
            {},
            listener::ListenerEvidenceKind::ExactPositive,
            listener::DiagnosticPhase::Ownership,
            "missing child-owned exact-listener inode was accepted");
    rejects(exact,
            {111u, 999u},
            listener::ListenerEvidenceKind::ExactPositive,
            listener::DiagnosticPhase::Ownership,
            "extra absent-from-table child-owned inode was accepted");
    rejects(exact,
            {111u, 222u},
            listener::ListenerEvidenceKind::ExactPositive,
            listener::DiagnosticPhase::Ownership,
            "target-owned non-listening guard inode was accepted as RUT-child-owned");
    rejects(exact,
            {333u},
            listener::ListenerEvidenceKind::ExactPositive,
            listener::DiagnosticPhase::Evidence,
            "unrelated-port child-owned inode was accepted for exact listener");
    rejects(exact,
            {999u},
            listener::ListenerEvidenceKind::ExactPositive,
            listener::DiagnosticPhase::Evidence,
            "unowned exact listener was accepted");
    rejects(exact,
            {111u, 111u},
            listener::ListenerEvidenceKind::ExactPositive,
            listener::DiagnosticPhase::Ownership,
            "duplicate owned inode was accepted");
    rejects(exact,
            {0u},
            listener::ListenerEvidenceKind::ExactPositive,
            listener::DiagnosticPhase::Ownership,
            "zero owned inode was accepted");
    rejects(exact,
            std::vector<std::uint64_t>(listener::kMaxOwnedSocketInodes + 1u, 1u),
            listener::ListenerEvidenceKind::ExactPositive,
            listener::DiagnosticPhase::Ownership,
            "over-bound owned inode set was accepted");

    listener::ProcTcpTable wildcard;
    ok =
        check(listener::parse_proc_net_tcp(
                  std::string(kHeader) + row("00000000:1F90", "0A", "444"), wildcard, diagnostic) &&
                  listener::classify_listener_evidence(wildcard,
                                                       kPlan,
                                                       {444u},
                                                       listener::ListenerEvidenceKind::Wildcard,
                                                       evidence,
                                                       diagnostic) &&
                  evidence.child_owned_inode == 444u && evidence.guard_covered_by_listener,
              "child-owned wildcard listener was not classified") &&
        ok;
    rejects(wildcard,
            {444u},
            listener::ListenerEvidenceKind::ExactPositive,
            listener::DiagnosticPhase::Evidence,
            "wildcard listener was accepted as exact");

    listener::ProcTcpTable absent;
    ok =
        check(
            listener::parse_proc_net_tcp(
                std::string(kHeader) + row("00000000:1F91", "0A", "666", 1u), absent, diagnostic) &&
                listener::classify_listener_evidence(absent,
                                                     kPlan,
                                                     {},
                                                     listener::ListenerEvidenceKind::PortAbsent,
                                                     evidence,
                                                     diagnostic) &&
                evidence.child_owned_inode == 0u && !evidence.guard_covered_by_listener,
            "complete selected-port absence was not classified") &&
        ok;
    rejects(absent,
            {666u},
            listener::ListenerEvidenceKind::PortAbsent,
            listener::DiagnosticPhase::Ownership,
            "unrelated-port child-owned inode was accepted for complete port absence");
    rejects(absent,
            {999u},
            listener::ListenerEvidenceKind::PortAbsent,
            listener::DiagnosticPhase::Ownership,
            "absent-from-table child-owned inode was accepted for complete port absence");

    listener::ProcTcpTable guard_reserved;
    ok =
        check(listener::parse_proc_net_tcp(std::string(kHeader) + row("0402010A:1F90", "07", "555"),
                                           guard_reserved,
                                           diagnostic),
              "guard reservation mutation table setup failed") &&
        ok;
    rejects(guard_reserved,
            {},
            listener::ListenerEvidenceKind::PortAbsent,
            listener::DiagnosticPhase::Evidence,
            "non-listening selected-port record was accepted as complete port absence");

    listener::ProcTcpTable guard_listening;
    ok =
        check(listener::parse_proc_net_tcp(std::string(kHeader) + row("0402010A:1F90", "0A", "777"),
                                           guard_listening,
                                           diagnostic),
              "guard listener mutation table setup failed") &&
        ok;
    rejects(guard_listening,
            {},
            listener::ListenerEvidenceKind::PortAbsent,
            listener::DiagnosticPhase::Evidence,
            "guard LISTEN record was accepted as complete port absence");

    listener::ProcTcpTable ambiguous = exact;
    ambiguous.rows[ambiguous.count++] = {0u, kPlan.port, 0x0au, 888u};
    rejects(ambiguous,
            {111u},
            listener::ListenerEvidenceKind::ExactPositive,
            listener::DiagnosticPhase::Evidence,
            "conflicting exact and wildcard listeners were accepted");
    ambiguous = exact;
    ambiguous.rows[ambiguous.count++] = exact.rows[0];
    rejects(ambiguous,
            {111u},
            listener::ListenerEvidenceKind::ExactPositive,
            listener::DiagnosticPhase::Evidence,
            "ambiguous duplicate exact listeners were accepted");
    return ok;
}

bool collision_log_tests() {
    constexpr char kSource[] = "/tmp/listener-:8080.rut";
    const std::string epoll =
        std::string("Loaded program: ") + kSource +
        " (opt O2)\nBackend: epoll\nFailed to create listen socket for shard 0 (errno=" +
        std::to_string(EADDRINUSE) + ", source=4)\n";
    listener::CollisionLogEvidence evidence;
    listener::Diagnostic diagnostic;
    bool ok = check(listener::classify_collision_log(epoll, kSource, 2u, evidence, diagnostic) &&
                        evidence.backend == listener::CollisionBackend::Epoll &&
                        evidence.optimization_level == 2u && evidence.error_number == EADDRINUSE &&
                        diagnostic.row_count == 3u && diagnostic.error_number == EADDRINUSE,
                    "exact epoll EADDRINUSE collision log was not classified");
    std::string io_uring = epoll;
    io_uring.replace(io_uring.find("Backend: epoll"), 14u, "Backend: io_uring");
    ok = check(listener::classify_collision_log(io_uring, kSource, 2u, evidence, diagnostic) &&
                   evidence.backend == listener::CollisionBackend::IoUring,
               "exact io_uring EADDRINUSE collision log was not classified") &&
         ok;
    auto rejects = [&](std::string mutation,
                       const std::string& expected_path,
                       std::uint8_t expected_opt,
                       const char* message) {
        listener::CollisionLogEvidence ignored;
        listener::Diagnostic failure;
        ok = check(!listener::classify_collision_log(
                       mutation, expected_path, expected_opt, ignored, failure) &&
                       failure.phase == listener::DiagnosticPhase::CollisionLog,
                   message) &&
             ok;
    };
    std::string mutation = epoll;
    mutation.replace(mutation.find(":8080"), 5u, ":8081");
    rejects(mutation, kSource, 2u, "wrong source endpoint was accepted");
    mutation = epoll;
    mutation.replace(mutation.find("O2"), 2u, "O1");
    rejects(mutation, kSource, 2u, "wrong optimization record was accepted");
    mutation = epoll;
    mutation.replace(mutation.find("Backend: epoll"), 14u, "Backend: epoll (TLS)");
    rejects(mutation, kSource, 2u, "unrecognized backend record was accepted");
    mutation = epoll;
    mutation.replace(mutation.find("errno=98"), 8u, "errno=99");
    rejects(mutation, kSource, 2u, "wrong bind errno was accepted");
    mutation = epoll;
    mutation.replace(mutation.find("source=4"), 8u, "source=3");
    rejects(mutation, kSource, 2u, "wrong bind error source was accepted");
    mutation = epoll;
    mutation.replace(mutation.find("shard 0"), 7u, "shard 1");
    rejects(mutation, kSource, 2u, "wrong failed shard was accepted");
    rejects(epoll + "Loaded program: duplicate (opt O2)\n",
            kSource,
            2u,
            "duplicate source-load record was accepted");
    rejects("Backend: epoll\n" + epoll, kSource, 2u, "duplicate backend record was accepted");
    rejects(epoll + "Listening on port 8080 with 1 shard(s)\n",
            kSource,
            2u,
            "listening-success record was accepted");
    rejects(epoll.substr(0u, epoll.size() - 1u), kSource, 2u, "truncated log was accepted");
    rejects(std::string(listener::kMaxCollisionLogBytes + 1u, 'x') + "\n",
            kSource,
            2u,
            "over-bound log was accepted");
    mutation = epoll;
    mutation[mutation.find("Backend")] = '\0';
    rejects(mutation, kSource, 2u, "embedded NUL log was accepted");
    rejects(epoll, "/tmp/bad\nsource.rut", 2u, "unsafe expected source path was accepted");
    rejects(epoll, kSource, 4u, "out-of-range expected optimization level was accepted");
    return ok;
}

}  // namespace

int main() {
    const bool ok = plan_and_source_tests() && proc_parser_tests() && guard_reservation_tests() &&
                    evidence_tests() && collision_log_tests();
    if (!ok) return 1;
    std::puts("PASS: #358 pure listener evidence helper");
    return 0;
}
