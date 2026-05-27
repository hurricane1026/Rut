# Firewall (runtime RouteConfig)

This document describes the firewall capability currently available in runtime
configuration (`RouteConfig`), independent of DSL parsing.

## Scope

Current support is IPv4 source-address filtering on accepted downstream
connections.

- Exact IP rules
- CIDR subnet rules
- Allowlist + denylist precedence

Rules are evaluated from `Connection.peer_addr` captured at accept-time.
For host-order callers, `firewall_allows_peer_host(u32)` is also available.

## APIs

Defined on `RouteConfig`:

- `add_firewall_allow_ip(u32 ip_host_order)`
- `add_firewall_deny_ip(u32 ip_host_order)`
- `add_firewall_allow_cidr(u32 ip_host_order, u8 prefix_len)`
- `add_firewall_deny_cidr(u32 ip_host_order, u8 prefix_len)`
- `remove_firewall_allow_ip(u32 ip_host_order)`
- `remove_firewall_deny_ip(u32 ip_host_order)`
- `remove_firewall_allow_cidr(u32 ip_host_order, u8 prefix_len)`
- `remove_firewall_deny_cidr(u32 ip_host_order, u8 prefix_len)`
- `add_firewall_allow_ip("a.b.c.d")`
- `add_firewall_deny_ip("a.b.c.d")`
- `add_firewall_allow_cidr("a.b.c.d/prefix")`
- `add_firewall_deny_cidr("a.b.c.d/prefix")`
- `remove_firewall_allow_ip("a.b.c.d")`
- `remove_firewall_deny_ip("a.b.c.d")`
- `remove_firewall_allow_cidr("a.b.c.d/prefix")`
- `remove_firewall_deny_cidr("a.b.c.d/prefix")`
- `clear_firewall_rules()`

All `u32` IPv4 arguments are host-order (same convention as
`UpstreamTarget::set_addr`).
Firewall tables also store rule IP values in host-order.
String overloads parse dotted IPv4/CIDR literals and return `false` on
malformed input.
`Connection.peer_addr` comes from accept/getpeername in network byte order;
the runtime converts as needed during firewall evaluation.

Each rule family currently has a fixed cap (`kMaxFirewallRules`), and add APIs
return `false` on cap overflow or invalid CIDR prefix.
Adding the same exact IP or same CIDR repeatedly is idempotent (returns `true`
without consuming additional rule slots).
Remove APIs return `true` only when a matching rule exists and is deleted.
`clear_firewall_rules()` clears all allow/deny exact and CIDR rules.

## Evaluation order

For each request:

1. Any deny IP match => reject
2. Any deny CIDR match => reject
3. If no allow rules exist => allow
4. Otherwise require allow IP or allow CIDR match

In other words, deny rules always win over allow rules.

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
cfg.add_firewall_allow_cidr(0x0a000000, 8);   // 10.0.0.0/8
cfg.add_firewall_deny_cidr(0x0a010000, 16);   // 10.1.0.0/16
cfg.add_firewall_allow_ip(0x7f000001);        // 127.0.0.1
```

## Tests

Coverage is in `tests/test_network.cc` under `route_coverage`:

- `firewall_deny_rule_returns_403`
- `firewall_allowlist_blocks_non_members`
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

Integration coverage in `tests/test_integration.cc` includes:

- `firewall_deny_localhost_real_socket`
- `firewall_deny_localhost_cidr_real_socket`
- `firewall_allowlist_exact_localhost_real_socket`
- `firewall_deny_exact_over_allow_exact_real_socket`
- `firewall_allowlist_cidr_localhost_real_socket`
- `firewall_clear_rules_reenables_localhost_real_socket`
- `firewall_remove_deny_rule_reenables_localhost_real_socket`
- `firewall_remove_deny_cidr_reenables_localhost_real_socket`
- `firewall_remove_allow_rule_restores_default_allow_real_socket`
- `firewall_remove_allow_cidr_restores_default_allow_real_socket`
- `firewall_remove_deny_cidr_restores_allow_cidr_real_socket`
- `firewall_remove_deny_ip_restores_allow_ip_real_socket`
- `firewall_remove_last_allow_ip_keeps_deny_cidr_real_socket`
- `firewall_remove_last_allow_cidr_keeps_deny_ip_real_socket`
