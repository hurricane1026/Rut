#include "fixture_privileged_listener.h"

#include "rut/runtime/error.h"
#include <algorithm>
#include <cerrno>
#include <charconv>
#include <limits>
#include <string_view>

namespace rut::test::fixture_privileged_listener {
namespace {

constexpr std::uint8_t kTcpListen = 0x0au;
constexpr std::uint8_t kSocketErrorSource = static_cast<std::uint8_t>(rut::Error::Source::Socket);
constexpr std::size_t kMaxSourceBytes = 256u;
constexpr std::size_t kMaxLineBytes = 512u;
constexpr std::size_t kMaxTokensPerLine = 32u;

void fail(Diagnostic& diagnostic,
          DiagnosticPhase phase,
          std::size_t rows = 0u,
          std::size_t matches = 0u,
          std::size_t owned = 0u,
          int error_number = 0) {
    diagnostic = {phase, rows, matches, owned, error_number};
}

bool is_loopback(std::uint32_t address) {
    return (address >> 24u) == 127u;
}

std::string ipv4_text(std::uint32_t address) {
    return std::to_string((address >> 24u) & 0xffu) + "." +
           std::to_string((address >> 16u) & 0xffu) + "." +
           std::to_string((address >> 8u) & 0xffu) + "." + std::to_string(address & 0xffu);
}

bool parse_unsigned(std::string_view value, int base, std::uint64_t maximum, std::uint64_t& out) {
    if (value.empty()) return false;
    std::uint64_t parsed = 0u;
    const char* const begin = value.data();
    const char* const end = begin + value.size();
    const auto result = std::from_chars(begin, end, parsed, base);
    if (result.ec != std::errc{} || result.ptr != end || parsed > maximum) return false;
    out = parsed;
    return true;
}

bool split_tokens(std::string_view line,
                  std::array<std::string_view, kMaxTokensPerLine>& tokens,
                  std::size_t& count) {
    count = 0u;
    std::size_t cursor = 0u;
    while (cursor < line.size()) {
        while (cursor < line.size() && (line[cursor] == ' ' || line[cursor] == '\t')) cursor++;
        if (cursor == line.size()) break;
        const std::size_t begin = cursor;
        while (cursor < line.size() && line[cursor] != ' ' && line[cursor] != '\t') cursor++;
        if (count == tokens.size() || cursor - begin > 64u) return false;
        tokens[count++] = line.substr(begin, cursor - begin);
    }
    return true;
}

bool parse_endpoint(std::string_view token, std::uint32_t& ipv4, std::uint16_t& port) {
    if (token.size() != 13u || token[8] != ':') return false;
    std::uint64_t raw_address = 0u;
    std::uint64_t raw_port = 0u;
    if (!parse_unsigned(token.substr(0u, 8u), 16, 0xffffffffu, raw_address) ||
        !parse_unsigned(token.substr(9u, 4u), 16, 0xffffu, raw_port))
        return false;
    const std::uint32_t value = static_cast<std::uint32_t>(raw_address);
    ipv4 = ((value & 0x000000ffu) << 24u) | ((value & 0x0000ff00u) << 8u) |
           ((value & 0x00ff0000u) >> 8u) | ((value & 0xff000000u) >> 24u);
    port = static_cast<std::uint16_t>(raw_port);
    return true;
}

bool valid_owned_inodes(const std::vector<std::uint64_t>& inodes) {
    if (inodes.size() > kMaxOwnedSocketInodes) return false;
    for (std::size_t i = 0u; i < inodes.size(); ++i) {
        if (inodes[i] == 0u) return false;
        for (std::size_t j = i + 1u; j < inodes.size(); ++j)
            if (inodes[i] == inodes[j]) return false;
    }
    return true;
}

bool is_owned(std::uint64_t inode, const std::vector<std::uint64_t>& owned) {
    return std::find(owned.begin(), owned.end(), inode) != owned.end();
}

bool safe_text(const std::string& value, std::size_t maximum) {
    if (value.empty() || value.size() > maximum) return false;
    for (const unsigned char byte : value)
        if (byte < 0x20u || byte > 0x7eu) return false;
    return true;
}

}  // namespace

bool validate_listener_plan(const ListenerPlan& plan,
                            ListenerPlanText& text,
                            Diagnostic& diagnostic) {
    text = {};
    diagnostic = {};
    if (plan.port == 0u || plan.port > std::numeric_limits<std::uint16_t>::max() ||
        plan.positive_ipv4 == 0u || plan.guard_ipv4 == 0u ||
        plan.positive_ipv4 == plan.guard_ipv4 || is_loopback(plan.positive_ipv4) ||
        is_loopback(plan.guard_ipv4)) {
        fail(diagnostic, DiagnosticPhase::Plan);
        return false;
    }
    text.positive_ipv4 = ipv4_text(plan.positive_ipv4);
    text.guard_ipv4 = ipv4_text(plan.guard_ipv4);
    const std::string port = std::to_string(plan.port);
    text.positive_endpoint = text.positive_ipv4 + ":" + port;
    text.guard_endpoint = text.guard_ipv4 + ":" + port;
    text.wildcard_endpoint = ":" + port;
    return true;
}

bool build_listener_source(const ListenerPlan& plan,
                           ListenerSourceKind kind,
                           std::string& source,
                           Diagnostic& diagnostic) {
    source.clear();
    ListenerPlanText text;
    if (!validate_listener_plan(plan, text, diagnostic)) return false;
    if (kind != ListenerSourceKind::Exact && kind != ListenerSourceKind::Wildcard) {
        fail(diagnostic, DiagnosticPhase::Source);
        return false;
    }
    const std::string endpoint =
        kind == ListenerSourceKind::Exact ? text.positive_endpoint : text.wildcard_endpoint;
    source = "listen " + endpoint + "\n" +
             "route exact slash_normalized GET \"/\" { return local_response({ status: 204 }) "
             "}\n";
    if (source.size() > kMaxSourceBytes) {
        fail(diagnostic, DiagnosticPhase::Source);
        return false;
    }
    diagnostic = {};
    return true;
}

bool parse_proc_net_tcp(const std::string& contents, ProcTcpTable& table, Diagnostic& diagnostic) {
    table = {};
    diagnostic = {};
    if (contents.empty() || contents.size() > kMaxProcBytes || contents.back() != '\n' ||
        contents.find('\0') != std::string::npos) {
        fail(diagnostic, DiagnosticPhase::ProcHeader);
        return false;
    }

    std::size_t offset = 0u;
    std::size_t line_number = 0u;
    while (offset < contents.size()) {
        const std::size_t newline = contents.find('\n', offset);
        if (newline == std::string::npos || newline - offset > kMaxLineBytes) {
            fail(diagnostic, DiagnosticPhase::ProcRow, table.count);
            return false;
        }
        const std::string_view line(contents.data() + offset, newline - offset);
        offset = newline + 1u;
        std::array<std::string_view, kMaxTokensPerLine> tokens{};
        std::size_t token_count = 0u;
        if (!split_tokens(line, tokens, token_count)) {
            fail(diagnostic,
                 line_number == 0u ? DiagnosticPhase::ProcHeader : DiagnosticPhase::ProcRow,
                 table.count);
            return false;
        }
        if (line_number++ == 0u) {
            static constexpr std::array<std::string_view, 10> kHeader{"sl",
                                                                      "local_address",
                                                                      "rem_address",
                                                                      "st",
                                                                      "tx_queue",
                                                                      "rx_queue",
                                                                      "tr",
                                                                      "tm->when",
                                                                      "retrnsmt",
                                                                      "uid"};
            // Linux prints "tx_queue rx_queue" and "tr tm->when" as header pairs, while data
            // folds each pair into one colon-separated token. Require the stable named prefix
            // through inode, accepting either kernel whitespace grouping.
            const bool canonical =
                token_count >= 12u && tokens[0] == kHeader[0] && tokens[1] == kHeader[1] &&
                tokens[2] == kHeader[2] && tokens[3] == kHeader[3] && tokens[4] == kHeader[4] &&
                tokens[5] == kHeader[5] && tokens[6] == kHeader[6] && tokens[7] == kHeader[7] &&
                tokens[8] == kHeader[8] && tokens[9] == kHeader[9] && tokens[10] == "timeout" &&
                tokens[11] == "inode";
            if (!canonical) {
                fail(diagnostic, DiagnosticPhase::ProcHeader);
                return false;
            }
            continue;
        }
        if (line.empty()) {
            fail(diagnostic, DiagnosticPhase::ProcRow, table.count);
            return false;
        }
        if (token_count < 10u || table.count == table.rows.size()) {
            fail(diagnostic, DiagnosticPhase::ProcRow, table.count);
            return false;
        }
        std::uint64_t slot = 0u;
        if (tokens[0].back() != ':' || !parse_unsigned(tokens[0].substr(0u, tokens[0].size() - 1u),
                                                       10,
                                                       std::numeric_limits<std::uint32_t>::max(),
                                                       slot)) {
            fail(diagnostic, DiagnosticPhase::ProcRow, table.count);
            return false;
        }
        ProcTcpRecord record{};
        std::uint32_t remote_ipv4 = 0u;
        std::uint16_t remote_port = 0u;
        std::uint64_t state = 0u;
        if (!parse_endpoint(tokens[1], record.local_ipv4, record.local_port) ||
            !parse_endpoint(tokens[2], remote_ipv4, remote_port) || tokens[3].size() != 2u ||
            !parse_unsigned(tokens[3], 16, 0xffu, state) ||
            !parse_unsigned(
                tokens[9], 10, std::numeric_limits<std::uint64_t>::max(), record.inode)) {
            fail(diagnostic, DiagnosticPhase::ProcRow, table.count);
            return false;
        }
        record.state = static_cast<std::uint8_t>(state);
        for (std::size_t i = 0u; i < table.count; ++i) {
            const ProcTcpRecord& prior = table.rows[i];
            const bool duplicate_record =
                prior.local_ipv4 == record.local_ipv4 && prior.local_port == record.local_port &&
                prior.state == record.state && prior.inode == record.inode;
            const bool reused_inode = record.inode != 0u && prior.inode == record.inode;
            if (duplicate_record || reused_inode) {
                fail(diagnostic, DiagnosticPhase::ProcRow, table.count);
                return false;
            }
        }
        table.rows[table.count++] = record;
    }
    diagnostic.row_count = table.count;
    return true;
}

bool classify_listener_evidence(const ProcTcpTable& table,
                                const ListenerPlan& plan,
                                const std::vector<std::uint64_t>& child_owned_socket_inodes,
                                ListenerEvidenceKind expected,
                                ListenerEvidence& evidence,
                                Diagnostic& diagnostic) {
    evidence = {};
    diagnostic = {};
    ListenerPlanText text;
    if (!validate_listener_plan(plan, text, diagnostic)) return false;
    if (table.count > table.rows.size() || !valid_owned_inodes(child_owned_socket_inodes)) {
        fail(diagnostic, DiagnosticPhase::Ownership, table.count);
        return false;
    }
    const bool listener_expected = expected == ListenerEvidenceKind::ExactPositive ||
                                   expected == ListenerEvidenceKind::Wildcard;
    if ((listener_expected && child_owned_socket_inodes.size() != 1u) ||
        (expected == ListenerEvidenceKind::PortAbsent && !child_owned_socket_inodes.empty())) {
        fail(diagnostic,
             DiagnosticPhase::Ownership,
             table.count,
             0u,
             child_owned_socket_inodes.size());
        return false;
    }
    if (!listener_expected && expected != ListenerEvidenceKind::PortAbsent) {
        fail(diagnostic, DiagnosticPhase::Evidence, table.count);
        return false;
    }
    const std::uint16_t selected_port = static_cast<std::uint16_t>(plan.port);

    std::size_t listeners = 0u;
    std::size_t port_records = 0u;
    std::size_t positive = 0u;
    std::size_t wildcard = 0u;
    std::size_t guard = 0u;
    std::size_t owned = 0u;
    std::uint64_t selected_inode = 0u;
    for (std::size_t i = 0u; i < table.count; ++i) {
        const ProcTcpRecord& row = table.rows[i];
        if (row.local_port != selected_port) continue;
        port_records++;
        if (row.state != kTcpListen) continue;
        listeners++;
        if (row.local_ipv4 == plan.positive_ipv4) positive++;
        if (row.local_ipv4 == 0u) wildcard++;
        if (row.local_ipv4 == plan.guard_ipv4) guard++;
        if (is_owned(row.inode, child_owned_socket_inodes)) {
            owned++;
            selected_inode = row.inode;
        }
    }

    const bool exact_ok = expected == ListenerEvidenceKind::ExactPositive && listeners == 1u &&
                          positive == 1u && wildcard == 0u && guard == 0u && owned == 1u;
    const bool wildcard_ok = expected == ListenerEvidenceKind::Wildcard && listeners == 1u &&
                             positive == 0u && wildcard == 1u && guard == 0u && owned == 1u;
    const bool absent_ok = expected == ListenerEvidenceKind::PortAbsent && port_records == 0u &&
                           listeners == 0u && positive == 0u && wildcard == 0u && guard == 0u &&
                           owned == 0u;
    if (!exact_ok && !wildcard_ok && !absent_ok) {
        fail(diagnostic,
             DiagnosticPhase::Evidence,
             table.count,
             expected == ListenerEvidenceKind::PortAbsent ? port_records : listeners,
             owned);
        return false;
    }
    evidence.kind = expected;
    evidence.guard_covered_by_listener = expected == ListenerEvidenceKind::Wildcard;
    evidence.child_owned_inode = expected == ListenerEvidenceKind::PortAbsent ? 0u : selected_inode;
    diagnostic = {DiagnosticPhase::None,
                  table.count,
                  expected == ListenerEvidenceKind::PortAbsent ? port_records : listeners,
                  owned,
                  0};
    return true;
}

bool classify_collision_log(const std::string& log,
                            const std::string& expected_source_path,
                            std::uint8_t expected_optimization_level,
                            CollisionLogEvidence& evidence,
                            Diagnostic& diagnostic) {
    evidence = {};
    diagnostic = {};
    if (!safe_text(expected_source_path, 256u) || expected_optimization_level > 3u || log.empty() ||
        log.size() > kMaxCollisionLogBytes || log.back() != '\n' ||
        log.find('\0') != std::string::npos ||
        log.find("Listening on port ") != std::string::npos) {
        fail(diagnostic, DiagnosticPhase::CollisionLog);
        return false;
    }

    std::array<std::string_view, 4> lines{};
    std::size_t count = 0u;
    std::size_t offset = 0u;
    while (offset < log.size()) {
        const std::size_t newline = log.find('\n', offset);
        if (newline == std::string::npos || newline - offset > kMaxLineBytes ||
            count == lines.size()) {
            fail(diagnostic, DiagnosticPhase::CollisionLog, count);
            return false;
        }
        lines[count++] = std::string_view(log).substr(offset, newline - offset);
        offset = newline + 1u;
    }
    const std::string loaded = "Loaded program: " + expected_source_path + " (opt O" +
                               std::to_string(expected_optimization_level) + ")";
    const std::string failure =
        "Failed to create listen socket for shard 0 (errno=" + std::to_string(EADDRINUSE) +
        ", source=" + std::to_string(kSocketErrorSource) + ")";
    if (count != 3u || lines[0] != loaded || lines[2] != failure) {
        fail(diagnostic, DiagnosticPhase::CollisionLog, count);
        return false;
    }
    if (lines[1] == "Backend: epoll")
        evidence.backend = CollisionBackend::Epoll;
    else if (lines[1] == "Backend: io_uring")
        evidence.backend = CollisionBackend::IoUring;
    else {
        fail(diagnostic, DiagnosticPhase::CollisionLog, count);
        return false;
    }
    evidence.optimization_level = expected_optimization_level;
    evidence.error_number = EADDRINUSE;
    diagnostic = {DiagnosticPhase::None, count, 1u, 0u, EADDRINUSE};
    return true;
}

}  // namespace rut::test::fixture_privileged_listener
