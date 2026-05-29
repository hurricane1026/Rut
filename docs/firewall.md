# Firewall (runtime RouteConfig)

This document describes the firewall capability currently available in runtime
configuration (`RouteConfig`), independent of DSL parsing.

## Scope

Current support is IPv4 source-address filtering on accepted downstream
connections.

- Exact IP rules
- CIDR subnet rules
- Inclusive IP range rules
- Source port rules
- Allowlist + denylist precedence

Rules are evaluated from `Connection.peer_addr` and `Connection.peer_port`
captured at accept-time.
For host-order callers, both `firewall_allows_peer_host(u32)` and
`firewall_allows_peer_host(u32, u16)` are available.

## APIs

Defined on `RouteConfig`:

- `add_firewall_allow_ip(u32 ip_host_order)`
- `add_firewall_deny_ip(u32 ip_host_order)`
- `add_firewall_allow_cidr(u32 ip_host_order, u8 prefix_len)`
- `add_firewall_deny_cidr(u32 ip_host_order, u8 prefix_len)`
- `add_firewall_allow_range(u32 start_ip_host_order, u32 end_ip_host_order)`
- `add_firewall_deny_range(u32 start_ip_host_order, u32 end_ip_host_order)`
- `add_firewall_allow_port(u16 peer_port_host_order)`
- `add_firewall_deny_port(u16 peer_port_host_order)`
- `remove_firewall_allow_ip(u32 ip_host_order)`
- `remove_firewall_deny_ip(u32 ip_host_order)`
- `remove_firewall_allow_cidr(u32 ip_host_order, u8 prefix_len)`
- `remove_firewall_deny_cidr(u32 ip_host_order, u8 prefix_len)`
- `remove_firewall_allow_range(u32 start_ip_host_order, u32 end_ip_host_order)`
- `remove_firewall_deny_range(u32 start_ip_host_order, u32 end_ip_host_order)`
- `remove_firewall_allow_port(u16 peer_port_host_order)`
- `remove_firewall_deny_port(u16 peer_port_host_order)`
- `add_firewall_allow_ip_network_order(u32 ip_network_order)`
- `add_firewall_deny_ip_network_order(u32 ip_network_order)`
- `add_firewall_allow_cidr_network_order(u32 ip_network_order, u8 prefix_len)`
- `add_firewall_deny_cidr_network_order(u32 ip_network_order, u8 prefix_len)`
- `add_firewall_allow_range_network_order(u32 start_ip_network_order, u32 end_ip_network_order)`
- `add_firewall_deny_range_network_order(u32 start_ip_network_order, u32 end_ip_network_order)`
- `remove_firewall_allow_ip_network_order(u32 ip_network_order)`
- `remove_firewall_deny_ip_network_order(u32 ip_network_order)`
- `remove_firewall_allow_cidr_network_order(u32 ip_network_order, u8 prefix_len)`
- `remove_firewall_deny_cidr_network_order(u32 ip_network_order, u8 prefix_len)`
- `remove_firewall_allow_range_network_order(u32 start_ip_network_order, u32 end_ip_network_order)`
- `remove_firewall_deny_range_network_order(u32 start_ip_network_order, u32 end_ip_network_order)`
- `add_firewall_allow_ip("a.b.c.d")`
- `add_firewall_deny_ip("a.b.c.d")`
- `add_firewall_allow_cidr("a.b.c.d/prefix")`
- `add_firewall_deny_cidr("a.b.c.d/prefix")`
- `add_firewall_allow_range("a.b.c.d-e.f.g.h")`
- `add_firewall_deny_range("a.b.c.d-e.f.g.h")`
- `remove_firewall_allow_ip("a.b.c.d")`
- `remove_firewall_deny_ip("a.b.c.d")`
- `remove_firewall_allow_cidr("a.b.c.d/prefix")`
- `remove_firewall_deny_cidr("a.b.c.d/prefix")`
- `remove_firewall_allow_range("a.b.c.d-e.f.g.h")`
- `remove_firewall_deny_range("a.b.c.d-e.f.g.h")`
- `clear_firewall_allow_rules()`
- `clear_firewall_deny_rules()`
- `set_firewall_default_allow(bool allow)`
- `set_firewall_default_deny()`
- `firewall_default_is_allow()`
- `firewall_decision(u32 peer_addr_network_order)`
- `firewall_decision(u32 peer_addr_network_order, u16 peer_port_host_order)`
- `firewall_decision_host(u32 peer_addr_host_order)`
- `firewall_decision_host(u32 peer_addr_host_order, u16 peer_port_host_order)`
- `clear_firewall_rules()`

All `u32` IPv4 arguments are packed host-order values in the form
`(a << 24) | (b << 16) | (c << 8) | d` for `a.b.c.d` (same convention as
`UpstreamTarget::set_addr`).
Firewall tables also store rule IP values in host-order.
String overloads parse dotted IPv4/CIDR literals and return `false` on
malformed input.
`Connection.peer_addr` comes from accept/getpeername in network byte order;
`firewall_allows_peer` converts it once to packed host-order before evaluation.
For callers already holding network-order IPv4 (`in_addr.s_addr` style),
`*_network_order` helper overloads convert to packed host-order internally.

Each rule family currently has a fixed cap (`kMaxFirewallRules`), and add APIs
return `false` on cap overflow or invalid CIDR prefix.
Adding the same exact IP or same CIDR repeatedly is idempotent (returns `true`
without consuming additional rule slots).
Adding the same source port repeatedly is also idempotent (returns `true`
without consuming additional rule slots).
Port rules reject `0` (invalid TCP/UDP port).
Remove APIs return `true` only when a matching rule exists and is deleted.
`clear_firewall_allow_rules()` clears allow exact-IP, CIDR, range, and port tables.
`clear_firewall_deny_rules()` clears deny exact-IP, CIDR, range, and port tables.
`clear_firewall_rules()` clears all allow/deny exact, CIDR, range, and port rules.
`clear_firewall_allow_rules()` clears allow exact-IP, CIDR, range, and port tables.
`clear_firewall_deny_rules()` clears deny exact-IP, CIDR, range, and port tables.
`clear_firewall_rules()` clears all allow/deny exact, CIDR, range, and port rules.
Default policy is allow unless changed via `set_firewall_default_allow(false)`
or `set_firewall_default_deny()`.

## Evaluation order

For each request:

1. Any deny IP match => reject
2. Any deny CIDR match => reject
3. Any deny range match => reject
4. Any deny port match => reject
5. If no allow rules exist => apply default policy (allow by default)
6. Otherwise require allow IP, allow CIDR, allow range, or allow port match

In other words, deny rules always win over allow rules.
Allow-match semantics are OR across categories: if any allow IP, allow CIDR,
allow range, or allow port rule matches, the request is allowed (unless denied
earlier).

`firewall_decision(...)` returns a stable reason enum:

- allow: `AllowDefault`, `AllowAllowIp`, `AllowAllowCidr`, `AllowAllowPort`
- deny: `DenyDenyIp`, `DenyDenyCidr`, `DenyDenyPort`, `DenyMissingAllowMatch`

`firewall_allows_peer(u32)` / `firewall_allows_peer_host(u32)` and
`firewall_decision(u32)` / `firewall_decision_host(u32)` intentionally ignore
port tables to preserve legacy address-only semantics. Use the `(addr, port)`
overloads when source-port rules should be enforced.

For callers that just need category checks, use:

- `RouteConfig::firewall_decision_is_allow(...)`
- `RouteConfig::firewall_decision_is_deny(...)`

## Runtime behavior on reject

Firewall checks run in `on_header_received` before route matching.

On reject:

- response status is `403`
- response is sent immediately
- keep-alive is disabled for that connection

## Example

```cpp
RouteConfig cfg;
cfg.add_static("/ok", 0, 200);
cfg.add_firewall_allow_cidr(0x0a000000, 8);  // 10.0.0.0/8
cfg.add_firewall_deny_cidr(0x0a010000, 16);  // 10.1.0.0/16
cfg.add_firewall_allow_ip(0x7f000001);       // 127.0.0.1
```

## Tests

Current coverage in `tests/test_network.cc` (`route_coverage`) includes:

- `firewall_deny_rule_returns_403`
- `firewall_allowlist_blocks_non_members`
- `firewall_port_rejects_in_request_path`
- `firewall_cidr_allow_and_deny_rules`
- `firewall_string_ip_and_cidr_helpers`
- `firewall_exact_ip_rules_use_host_order_storage`
- `firewall_exact_ip_remove_roundtrip_with_network_peer_addr`
- `firewall_clear_rules_recovers_capacity`
- `firewall_remove_ip_and_cidr_rules`
- `firewall_remove_rejects_missing_or_invalid_rules`
- `firewall_remove_cidr_u32_rejects_invalid_prefix`
- `firewall_remove_allow_rules_updates_policy_mode`
- `firewall_remove_last_allow_keeps_deny_active`
- `firewall_remove_last_allow_cidr_keeps_deny_cidr_active`
- `firewall_remove_deny_restores_allow_match`
- `firewall_port_allow_and_deny_rules`
- `firewall_port_rule_remove_and_clear`
- `firewall_decision_reports_precedence_reason`
- `firewall_decision_reports_allow_reason_and_default_deny`
- `firewall_decision_host_helpers`
- `firewall_decision_allow_deny_classification_helpers`
- `firewall_decision_name_helper`
- `firewall_default_deny_requires_explicit_allow`
- `firewall_range_allow_and_deny_rules`
- `firewall_range_string_and_network_order_helpers`
- `firewall_range_rejects_invalid_inputs`

Current integration coverage in `tests/test_integration.cc` includes:

- `firewall_deny_localhost_real_socket`
- `firewall_deny_localhost_cidr_real_socket`
- `firewall_deny_localhost_network_order_real_socket`
- `firewall_allowlist_exact_localhost_real_socket`
- `firewall_deny_exact_over_allow_exact_real_socket`
- `firewall_deny_exact_over_allow_cidr_real_socket`
- `firewall_deny_cidr_over_allow_exact_real_socket`
- `firewall_allowlist_cidr_localhost_real_socket`
- `firewall_allowlist_network_order_cidr_localhost_real_socket`
- `firewall_deny_localhost_source_port_real_socket`
- `firewall_allowlist_source_port_real_socket`
- `firewall_clear_rules_reenables_localhost_real_socket`
- `firewall_remove_deny_rule_reenables_localhost_real_socket`
- `firewall_remove_deny_cidr_reenables_localhost_real_socket`
- `firewall_remove_allow_rule_restores_default_allow_real_socket`
- `firewall_remove_allow_cidr_restores_default_allow_real_socket`
- `firewall_remove_deny_cidr_restores_allow_cidr_real_socket`
- `firewall_remove_deny_ip_restores_allow_ip_real_socket`
- `firewall_remove_last_allow_ip_keeps_deny_cidr_real_socket`
- `firewall_remove_last_allow_cidr_keeps_deny_ip_real_socket`
- `firewall_default_deny_real_socket`
- `firewall_deny_localhost_range_real_socket`
- `firewall_allowlist_range_localhost_real_socket`
