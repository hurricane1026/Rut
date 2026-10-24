# TODO

Outstanding work items, prioritized for the next implementation passes.

## P0: Front-End Migration to the Revised Syntax Spec (branch design_syntax)

**Goal**: Migrate lexer/parser/checker to the 2026-07 DESIGN.md §3 revision
("Swift-exact or absent"). `docs/language-card.md` is the target surface;
each item should land with fix-it diagnostics matching DESIGN.md §3.6.

**Work** (roughly in dependency order):
- [x] Lexer: `&&` `||` `!` `!=` `<=` `>=` emitted; `and`/`or`/`not` lex to
  fix-it errors; lone `&`/`^`/`~` → bitwise.* fix-it; `?` → if-let fix-it
  (commit: slice 1). `respond` is implemented as a contextual statement word
  so user declarations and members may still use that name; `break`/`continue`
  remain pending with runtime `for` loops.
- [x] Parser: `!`/`!=`/`<=`/`>=` desugar to Eq/Lt/Gt (+ `== false` wrap);
  `&&` binds tighter than `||` (slice 1). Caseless match arms at all five
  sites with `case`/`:` fix-its + cross-line-dot arm boundary rule
  (slice 2a). `guard let x` shorthand (slice 2b-1).
- [x] Parser/analyze: `if let name = expr { } else { }` — parses like
  guard-let (bind_value/name/expr reused on the If stmt at both parse sites).
  Every non-const If analysis site (analyze.cc: analyze_function_body_stmt,
  analyze_match_arm_body, analyze_guard_fail_body, analyze_control_stmt) lowers
  the cond to HirExprKind::HasValue(expr) via analyze_guard_cond (known-value
  folding + pure-optional rejection reused) and injects a narrowed HirLocal
  (make_if_let_local → make_guard_bound_init) into the THEN-branch scope only
  (else/continuation never see it). Terminator-branch sites only swap the cond
  (binding unreferenceable there). Pure-optional carriers are covered by the
  lowering item below.
- [x] `respond status[, body]` statement — contextual parsing, literal-status
  validation, HIR `ReturnStatus`, helper propagation, and respond-capable
  `chain before` steps are implemented. `respond resp` accepts a Response
  builder and preserves its ordered literal `set`/`add`/`remove` header prefix
  through helper propagation. `chain after` helpers with exactly one `Response`
  parameter can apply ordered runtime header mutations to successful direct and
  forwarded responses; short-circuit branches do not publish those effects.
- [x] `guard` condition bool-only check + fix-it; guard-let usable-value
  semantics: known nil/error inits fold the condition to false (else always
  runs, binding skipped for known error); runtime error-capable inits lower
  to a HasValue condition with the bound local narrowed (review follow-up).
- [x] Lowering: opt carrier for pure-optional values (`may_nil` without
  `may_error`) — the Optional<inner> carrier substrate (opt_is_nil/opt_unwrap,
  req.query's Optional<Str>, opt-typed local storage) already existed; the
  guard-let/if-let rejection is lifted: analyze_guard_cond emits HasValue for
  pure-optional sources too, make_guard_bound_init ValueOf-wraps them, and
  the narrowed binding clears may_nil (e2e: guard/if-let over req.query,
  req.header, an optional-struct func result, and the `guard let q`
  shorthand).
- [x] Runtime ordering: guard-let over a runtime error value now wins over
  the resume-state-0 error prelude — RecoveryScan treats a bare
  HasValue(LocalRef) guard condition as a recovering use, so the prelude
  skips locals whose error the guard consumes (e2e: pick(req.http11) ->
  200 / guard else 401).
- [x] Error-prelude suppression: upgrade the linear-dominance walk to real
  per-local exit-dominance so a recovery behind a benign pre-reject
  (`guard ok else { return 403 }` before `wait`/recovery) can suppress the
  prelude WITHOUT letting a terminating sibling that returns success mask
  an unrecovered error (see
  conditional_guard_keeps_error_prelude_on_unguarded_sibling — the two
  shapes are structurally identical to a single-continuation walk; only
  exit-dominance separates them). Until then: conservative over-keep.
- [x] WebSocket terminate trailing blocks require the explicit
  `{ frame in ... }` binding; the legacy implicit-frame block is rejected.
- [x] Object literal syntax is accepted only in call-argument position and
  represented explicitly in the AST; bare/general-expression use is rejected.
  Still pending: `json()` lowering and runtime serialization.
- [x] Pipeline RHS validation requires a call stage with an explicit `_` / `_N`
  placeholder and reports the canonical placement fix-it before call analysis.
- Checker/builtins: [x] `.or(default)` (sugar for eager `any(value, default)`);
  [x] `req.params.*` capture namespace (flat `req.<capture>` is an error with a
  fix-it); [x] `bitwise.and/or/xor/flip/shiftLeft/shiftRight` namespace
  (end-to-end: analyze fold + HIR/MIR/RIR Bit* ops + LLVM codegen; i32/i64
  same-width operands, shifts saturate outside the width, `flip` desugars to
  `xor(a, -1)`; user bindings named `bitwise` shadow the namespace). Still
  [x] `Response` locals with ordered `set/remove/add/header`: literal prefixes
  fold into response-header sets and dynamic string values lower through a
  bounded per-request mutation log for direct routes; [x] `chain after`
  response-header mutation for direct and forwarded responses. Still pending:
  buffered body/status mutation and after middleware on `wait`/`for` routes
  (needs a resumable, stream-owned runtime Response);
  `req.queryAll` (needs a runtime [str] value type — none exists);
  `stats()/metrics()/reload()/upstream.mark()` declarations.
- Diagnostics: [x] §3.6 fix-its for `?.`/`??`, postfix `!`, truthiness
  guards, bitwise symbols, placeholder-less pipelines, and `case`/colon match
  arms; [x] middleware status-`return` and handler `respond` context errors
  with canonical replacement guidance.
- Tests/examples: migrate `examples/*.rut`, test fixtures, and docs/ topic
  pages (match.md, pipe.md, decorators.md, for-loops.md, ...) to the new
  surface once the front-end accepts it.

**Acceptance**: language-card examples all parse and type-check; old forms
produce the documented fix-its; `./dev.sh test` green.

## P1: State and Rate-Limit Semantics

**Goal**: Finish the state semantics exposed by the Cache/rate-limit slices
without presenting lossy or per-shard state as exact shared state.

**Work**:
- [x] Lower `Cache.set` at its branch position instead of only in the route-entry
  prelude. This enables a Rut limiter to commit the successor only on its
  accepted branch; the shipped example now demonstrates that policy.
- Design the strict, visible-failure `Hash` table and an owner-shard atomic
  update primitive before offering exact cross-shard rate limiting or state
  whose absence would be incorrect.
- Keep cross-node `backend:` syntax reserved until reads have an explicit
  freshness/invalidation contract; do not describe Cache as a source of truth.

**Acceptance**:
- A rate-limit test demonstrates both meter-every-attempt and meter-on-accept
  policies without special C++ rate-limit logic.
- Any exact shared-state surface specifies capacity failure, update atomicity,
  shard ownership, and read freshness before parser/runtime implementation.

## Recently Completed

- [x] Reject a fifth stacked `@rateLimit` decorator with a capacity diagnostic at
  that decorator, instead of silently omitting the rule. Boundary regression
  tests cover all four rules and independent per-route capacity.

- [x] Active global rate-limit rules fail closed when their shared limiter is
  missing, before spending earlier shard-rule budget. Disabled rules and normal
  startup wiring retain their behavior; shared enforcement has focused tests.

- [x] Kong/APISIX plan #819, M1 security primitive: `constantTimeEqual(str, str)`
  exposes bounded OpenSSL content comparison to Rut without a new keyword or
  dependency. Public lengths, 16 KiB failure limit, empty/binary semantics and
  user shadowing are documented; this does not complete the remaining random,
  key-handle, signature or certificate interfaces in M1.

- [x] Kong/APISIX plan #819 M1: request-owned `uuid() -> str?` uses OS CSPRNG
  entropy, RFC 9562 v4 formatting, explicit failures and bounded SliceArena
  storage. Direct-route-let and wait/timer/effect restrictions preserve evaluation and
  lifetime semantics; general byte arrays/randomBytes and request-ID header
  propagation remain separate follow-ups. Fresh expressions must gain single
  evaluation in guards/helper-local lowering before widening UUID placement.

- [x] Handler bodies reject `respond` with a `return` fix-it, while middleware
  functions reject status-`return` with a `respond` fix-it; valid helper
  `respond` propagation and ordinary function value expressions are unchanged.
- [x] `chain after` supports ordered `Response` header `set`/`add`/`remove`
  effects on successful direct and forwarded routes. Effects use the pending
  response mutation log and commit only on the selected success terminator;
  invalid helper shapes, empty-effect helpers, and wait/for routes are rejected
  with targeted diagnostics.
- [x] Dynamic direct-route Response mutations use a two-phase pending/commit
  log: `resp.header()` observes ordered pending writes, while only `return resp`
  publishes them. Guarded source-order lowering remains blocked until effects
  and their dependent reads can move out of the function prelude together.
- [x] Error-prelude exit-dominance now treats literal 4xx/5xx pre-rejects as
  fail-closed while keeping the prelude for success, redirect, dynamic, and
  forward exits that do not recover a fallible local.
- [x] Parser stack-frame slimming moved route statements and match-arm patterns
  into pools, fixing the gcc 16.1 Debug overflow; further slimming is only
  needed if frames grow again (PR #166).
- [x] `respond status[, body]` now short-circuits through helpers and
  respond-capable `chain before` steps; `respond` remains contextual.
- [x] `req.params.*` is the canonical route-capture namespace with a fix-it for
  the removed flat spelling.
- [x] `Cache<IP, i64>` provides bounded, lossy, per-shard state slots; i64
  arithmetic/bitwise operations and `time.nowMicros()` support Rut-written
  rate-limit algorithms.
- [x] `req.set("Name", "value")` and `req.add("Name", "value")` lower through
  HIR/MIR/RIR to the bounded request-header override runtime. `set` replaces and
  deduplicates existing fields; `add` preserves them and appends a new field.
  Both are statement-only, validate literal safe header names and values,
  support leading route statements and selected match-arm effects, and fail
  closed at runtime.
- [x] `let resp = response(status)` creates a compile-time Response builder;
  literal `resp.set/add/remove` mutations and `resp.header` reads fold in source
  order, `return resp` reuses the existing response-header-set ABI, and ordered
  duplicate names preserve multi-value fields such as `Set-Cookie`.
- [x] Dynamic `str` values in `resp.set/add` and ordered dynamic
  `resp.remove/header` lower through HIR/MIR/RIR/JIT into a bounded per-request
  mutation log. HTTP/1 and HTTP/2 merge it with the literal header prefix;
  invalid/overflowing mutations fail closed. Direct routes with guards,
  decorators, `wait`, or `for` remain rejected until mutations are stream-owned.
- [x] `examples/ratelimit.rut` demonstrates GCRA and fixed-window limiting over
  `Cache`; branch-local conditional writes support meter-on-accept policies.
- [x] epoll partial-send proactor semantics and recv-buffer integration.
- [x] io_uring timerfd timeout events and provided-buffer return path.
- [x] Shard runtime integration: per-core EventLoop, TimerWheel, route table, upstream pool, SlicePool, and SlabPool.
- [x] Connection buffers moved from inline storage to SlicePool-backed slices; free slots hold no slices; live connections keep recv/send slices bound, and on io_uring the dirty pages of idle plaintext HTTP/1.1 keep-alive connections (never TLS, h2 or WebSocket) idle >= ~5 s are returned via batched `MADV_DONTNEED` (`process_madvise`) when available.
- [x] Traffic replay now covers static/default paths and explicitly skips proxy routes through `replay_one`.
- [x] Capture persistence now covers raw-header tail zeroing, corrupted/truncated entries, zeroed entries, and EINTR retry for capture read/write.
- [x] Response parser rejects malformed status codes (`XYZ`, non-digit, `<100`, `>599`).
- [x] Simulate engine rejects malformed captured request headers and counts malformed capture entries as failed.
- [x] Proxy 502 paths assert `ConnState::Sending`; upstream connect failure now sets that state in production.
- [x] State invariant tests cover representative static, proxy, body-streaming, JIT-yield, idle, and 502 dispatch transitions.
- [x] Testing notes document the callback-slot/state invariants and the streaming-body exception.
- [x] Runtime debug helpers can snapshot and format connection state, callback slots, armed operations, and buffer lengths.
- [x] Test framework fault injection provides shared mmap/mprotect/socket/recv/poll/read/write/send/connect/epoll/timerfd/accept/open scopes for network/runtime tests.
- [x] Malformed upstream E2E coverage drives real proxy sockets through malformed status, EOF, header, and framing failures.
- [x] Replay/simulate route-action matrix coverage documents Static, Default, Proxy/JIT Forward, JIT ReturnStatus, mismatch, and malformed capture behavior.
- [x] Coverage helper now keeps the runtime threshold gate while printing per-area summaries for runtime, compiler, replay/sim, JIT, and optional changed first-party files.
- [x] Fault injection harness can now inject deterministic `clock_gettime` values and failures; access-log time helpers fail closed on clock errors.

## P0: State Invariant Coverage Follow-ups

**Goal**: Extend the newly added invariant checks to less-common transitions and keep the coverage aligned with future runtime changes.

**Why**: Baseline slot/state invariant coverage is now in place for representative static, proxy, body-streaming, JIT-yield, idle, and 502 dispatch transitions. The remaining work is to widen that coverage so new paths do not drift from the same debug/metrics expectations.

**Work**:
- Add follow-up tests for less-common or newly introduced transitions not yet covered by the representative dispatch cases.
- Reuse the existing invariant helper/check pattern when adding new dispatch paths or callback-slot combinations.
- Audit future state-machine changes for:
  - new `conn.state` values or transitions that need invariant assertions,
  - upstream error/timeout paths that may bypass the representative 502/500 cases,
  - teardown/reset flows where callback slots should be cleared before returning to idle/free states.

**Acceptance**:
- The backlog item is complete when remaining uncovered transitions have explicit invariant assertions or are documented as intentionally exempt.

## P1: Rut Core Syntax Reduction

**Goal**: Keep the stable language surface small enough for deterministic
review, verification, replay, and LLM-assisted generation.

**Why**: Rut has accumulated compatibility syntax for decorators, pipe method
stages, tuple-slot pipe placeholders, protocol-style methods, and match
expansions. Some of these are useful, but stable core syntax needs one
canonical spelling for common gateway tasks.

**Work**:
- Treat decorator syntax as compatibility and design `chain` as the stable
  before/after handler middleware model.
- Keep pipe in core, but document generated code around direct function stages:
  `value | fn(_, arg)`.
- Keep method-stage pipe syntax and tuple-slot pipe placeholders out of core
  examples unless compatibility requires them; placeholder-free stages are
  rejected by the stable grammar.
- Revisit protocol/impl exposure so protocol methods do not read like general
  structure member functions in generated Rut code.
- Audit `match` and generic examples for constructs that should be core,
  compatibility, or experimental.

**Acceptance**:
- Core docs distinguish stable core, compatibility, and experimental syntax.
- Generated examples use one canonical spelling for pipe, middleware, fallback,
  and async boundaries.
- Compatibility syntax has a clear lowering or migration path to core forms.

## P2: Coverage Tooling Hygiene

**Goal**: Make coverage reports actionable instead of broad percentage noise.

**Why**: The project has many generated, third-party, benchmark, and architecture-specific files. Raw coverage can hide runtime gaps or chase irrelevant files.

**Work**:
- Review `scripts/coverage_report.py` exclusions and CI coverage target.
- Keep per-area coverage summaries for runtime, compiler, replay/sim, and JIT actionable as test coverage changes.
- Wire changed-file coverage summaries into CI/PR output if the signal proves useful.

**Acceptance**:
- CI coverage output identifies the lowest-covered first-party runtime files.
- Third-party and benchmark files do not dominate coverage decisions.

## P2: TODO Maintenance

**Goal**: Keep this file as a live backlog, not a history log.

**Rules**:
- Move completed implementation milestones into `Recently Completed`.
- Keep active work scoped, prioritized, and testable.
- When review feedback creates a new recurring pattern, add it here with an acceptance criterion.

## Kong / Apache APISIX 场景对标待办（2026-10-16）

**目标**：记录 Kong Gateway 与 Apache APISIX 的场景范围，作为 Rut 后续能力
审计与规划的输入。以下覆盖本次整理的核心、官方插件及平台集成场景；第三方
插件和业务组合不是封闭集合，不宣称穷尽其全部可能性。

**状态与边界**：
- 所有复选框表示“Rut 对标审计与验收尚未完成”，不表示 Rut 当前不支持，也不表示
  已承诺实现。实施前对照当前代码、测试与 [语言卡](docs/language-card.md)，
  分别记录已支持、部分支持、缺失、不纳入范围。
- Kong 的“企业版”“AI 授权”“Konnect/Dev Portal 配套”分别标注；APISIX
  外部集成不等于内置对应服务。具体插件需要按目标版本和部署模式再次确认。
- “待核实”表示尚未确认直接对应能力，不能据此判断竞品完全不支持。
- 优先复用现有 Rut 语法和内部能力；本清单不授权新增关键字、依赖或后台任务。

### 1. 流量入口与协议

- [ ] REST API 统一入口、HTTP/HTTPS 反向代理：两者支持。
- [ ] HTTP/2、gRPC 服务入口：两者支持。
- [ ] 浏览器 gRPC-Web：Kong gRPC-Web；APISIX `grpc-web`。
- [ ] HTTP/JSON 到 gRPC 转码：Kong gRPC-Gateway；APISIX `grpc-transcode`。
- [ ] WebSocket 长连接代理：两者支持。
- [ ] WebSocket 逐消息大小限制与内容校验：Kong 专用企业版插件；APISIX 对应范围待核实。
- [ ] SSE、流式接口：两者可承载；需逐项验证缓冲、超时与客户端取消。
- [ ] TCP/UDP 四层代理：Kong 协议路由；APISIX Stream Proxy。
- [ ] TLS 终止、SNI 分流及 TLS 透传：核对两者对应路由与 Stream 配置。
- [ ] HTTP/3/QUIC：APISIX 文档标为实验性下游支持、不支持 HTTP/3 上游，
  不建议生产使用；Kong 对应范围待核实。
- [ ] MQTT 按 client_id 分流：APISIX `mqtt-proxy`，仅 Stream 模式；Kong 对应插件待核实。
- [ ] HTTP 到 Dubbo：APISIX `dubbo-proxy`、`http-dubbo`；Kong 需核实扩展方案。

### 2. 路由、服务发现与高可用

- [ ] Host 多域名、路径、请求方法路由：两者支持。
- [ ] 请求头、查询条件与表达式路由：核对 Kong 路由表达式与 APISIX 路由变量能力。
- [ ] API 多版本共存：通过 Route/Service 等资源组织。
- [ ] URL 前缀剥离、Host/URI 重写：路由配置与转换插件。
- [ ] 多实例与加权负载均衡：Kong Upstream/Target；APISIX Upstream。
- [ ] 根据客户端或请求属性进行哈希、保持后端选择：核实具体算法与会话语义。
- [ ] 主动健康检查、被动失败检测、故障摘除与恢复：两者支持对应机制。
- [ ] 上游连接/读写超时与重试：验证重试条件、次数及非幂等请求边界。
- [ ] DNS 服务发现：两者支持。
- [ ] 注册中心发现：APISIX DNS、Consul、Nacos、Eureka、Kubernetes 等；
  Kong 按具体集成核实。
- [ ] 蓝绿、金丝雀发布：Kong Canary Release 企业版等方案；APISIX `traffic-split`。
- [ ] 按用户或请求条件灰度：路由、流量标签及分流策略组合。
- [ ] 镜像与影子流量：APISIX `proxy-mirror`；Kong 直接对应方案待核实。
- [ ] 健康熔断与 API 熔断：Kong 健康检查/熔断；APISIX 健康检查及 `api-breaker`。

### 3. 身份认证与授权

- [ ] API Key、Basic、JWT、HMAC：两者有对应认证插件。
- [ ] LDAP 企业目录：Kong LDAP/企业版高级插件；APISIX LDAP 及版本相关高级插件。
- [ ] OIDC 单点登录、OAuth2 Token 内省：Kong 对应企业版插件；APISIX `openid-connect`。
- [ ] 网关 OAuth2 认证端点：Kong OAuth2 Authentication；APISIX 通常接外部 IdP。
- [ ] SAML 单点登录：Kong SAML 企业版；APISIX `saml-auth`。
- [ ] CAS、Keycloak、Casdoor：APISIX 专用插件/OIDC；Kong 按协议或扩展方案核实。
- [ ] 多种认证共存与匿名回退策略：Kong 插件组合；APISIX `multi-auth`。
- [ ] Consumer、分组及 API 访问范围：Kong Consumer/ACL；APISIX Consumer/Group/限制插件。
- [ ] OPA 策略授权：Kong 企业版；APISIX `opa`，策略引擎为外部服务。
- [ ] Casbin/Wolf RBAC：APISIX `authz-casbin`、`wolf-rbac`；Kong 集成方案待核实。
- [ ] 外部认证委托：APISIX `forward-auth`；Kong 对应调用或扩展方案待核实。
- [ ] JWE 解密：Kong 企业版；APISIX `jwe-decrypt`。
- [ ] JWT 验签与重新签发：Kong JWT Signer 企业版；APISIX 对应范围待核实。
- [ ] 获取访问上游所需 OAuth Token：Kong Upstream OAuth 企业版；APISIX 方案待核实。
- [ ] 客户端证书认证：Kong mTLS Authentication 企业版；APISIX mTLS 配置。
  分别审计双向 TLS 握手、证书身份映射与 API 授权。
- [ ] 身份会话管理、凭证轮转及跨网关身份复用：区分插件会话与 Kong Identity 等平台能力。

### 4. 安全与输入校验

- [ ] CORS、IP 白/黑名单：两者有对应插件。
- [ ] URI、User-Agent、Referer 规则拦截：APISIX 专用插件；Kong Bot Detection/路由/扩展组合。
- [ ] Consumer 访问限制与 ACL：两者对应资源与插件。
- [ ] CSRF：APISIX `csrf`；Kong 集成方案待核实。
- [ ] 请求体大小限制：Kong Request Size Limiting；APISIX `client-control` 等。
- [ ] 请求字段与结构校验：Kong Request Validator 企业版；APISIX `request-validation`。
- [ ] OpenAPI 请求校验：Kong OAS Validation 企业版；APISIX `oas-validator`。
- [ ] OpenAPI 响应校验：Kong OAS Validation 企业版；APISIX 版本支持范围待核实。
- [ ] JSON/XML 结构、深度与大小防护：Kong 专用企业版插件；APISIX 需核实组合或外部方案。
- [ ] 注入攻击与 Bot 防护：Kong Injection Protection 企业版/Bot Detection；
  APISIX 规则与 WAF 集成方案。
- [ ] WAF/WAAP/API 安全集成：Kong 第三方插件；APISIX `chaitin-waf` 接 SafeLine 等。
  不将连接器描述为内置完整 WAF。
- [ ] Webhook 签名规范验证：Kong Standard Webhooks；APISIX 对应方案待核实。
- [ ] TLS 证书、自动签发/轮换、OCSP、握手与证书元数据：逐项核实配置与插件；
  Kong 有 ACME 及部分企业版 TLS 插件，APISIX 有 OCSP/国密相关能力。
- [ ] 敏感数据脱敏：区分请求、响应、访问日志与 AI 内容，核实对应版本插件范围。

### 5. 限流、配额与服务保护

- [ ] 按 API、Consumer、IP 等维度限流：Kong Rate Limiting；APISIX 限流插件与键配置。
- [ ] 周期调用配额与多个限制窗口：Kong Rate Limiting；APISIX `limit-count`。
- [ ] 跨实例共享计数：两者对应存储策略；验证 Redis 故障与计数一致性。
- [ ] 滑动窗口与高级分布式限流：Kong Rate Limiting Advanced 企业版；
  APISIX 按具体算法与插件确认。
- [ ] 平滑突发与漏桶：APISIX `limit-req`；Kong 对应算法范围待核实。
- [ ] 并发限制：APISIX `limit-conn`；Kong 对应方案待核实。
- [ ] 服务整体保护额度：Kong Service Protection 企业版；APISIX 服务级插件策略。
- [ ] 根据响应计量值扣减额度：Kong Response Rate Limiting；APISIX 需核实扩展方案。
- [ ] GraphQL 查询成本限额：Kong 高级企业版插件；APISIX `graphql-limit-count`。
- [ ] AI Token 限额：Kong AI 授权插件；APISIX `ai-rate-limiting`。

### 6. 转换、适配与接口编排

- [ ] 请求头、查询参数增删改；Host、URI、方法重写：两者对应转换机制。
- [ ] 响应头、状态码、响应体修改：Kong Response Transformer 系列；APISIX `response-rewrite`。
- [ ] JSON/XML 等结构转换：Kong 高级转换/jq 等部分企业版；APISIX `body-transformer`。
- [ ] 复杂 JSON 处理：Kong jq 企业版；APISIX 模板、脚本或自定义插件。
- [ ] 自定义网关错误、维护页、固定响应：Kong Exit Transformer 企业版/Request Termination；
  APISIX `exit-transformer`、错误页与响应改写方案。
- [ ] URL 重定向与 HTTP 跳转 HTTPS：两者对应插件。
- [ ] REST/GraphQL 适配：分别核实两个方向，不能因插件都叫 DeGraphQL 就认定等价。
  Kong 企业版 DeGraphQL 将 GraphQL 上游暴露为 REST；APISIX 目录描述为 GraphQL 到 REST 上游。
- [ ] 批量 HTTP 请求及响应汇总：Kong Datakit 等企业版方案；APISIX `batch-requests`。
- [ ] 外部 API Callout、结果参与后续处理：Kong Request Callout/Datakit 企业版；
  APISIX Serverless/自定义插件等方案。
- [ ] 条件工作流：Kong 插件/Datakit；APISIX `workflow`。
- [ ] API Mock：Kong Mocking 企业版；APISIX `mocking`。
- [ ] 故障、延迟注入：APISIX `fault-injection`；Kong 对应测试或扩展方案待核实。

### 7. 缓存与传输优化

- [ ] HTTP 响应缓存：Kong Proxy Cache；APISIX `proxy-cache`。
- [ ] Redis 等高级缓存：Kong Proxy Cache Advanced 企业版；APISIX 按具体后端确认。
- [ ] GraphQL 查询缓存：Kong 高级企业版插件；APISIX `graphql-proxy-cache`，mutation 绕过缓存。
- [ ] LLM 结果/语义缓存：Kong AI Semantic Cache（AI 授权）；APISIX `ai-cache`。
- [ ] Gzip/Brotli 压缩：APISIX 对应插件；Kong 底层配置支持范围待核实。
- [ ] 请求/响应缓冲、背压与流式传输：两者代理配置与插件，逐项核实内存和取消行为。
- [ ] 上游连接复用与 Keep-Alive：两者支持；核实连接池与协议边界。

### 8. 可观测性与排障

- [ ] 请求量、延迟、错误率：Kong Prometheus/Datadog/StatsD；APISIX Prometheus/Datadog 等。
- [ ] 分布式追踪：两者 OpenTelemetry/Zipkin；APISIX 另有 SkyWalking。
- [ ] 请求 ID 与上下游日志关联：Kong Correlation ID；APISIX `request-id`。
- [ ] 文件、HTTP、TCP、UDP、Syslog 日志：两者对应插件。
- [ ] Kafka 日志：Kong 企业版；APISIX `kafka-logger`。
- [ ] RocketMQ、ClickHouse、Elasticsearch、Loki、Splunk、Loggly 等日志接入：
  APISIX 专用插件；Kong 按官方/第三方插件分别核实。
- [ ] 云日志：APISIX 阿里云 SLS、腾讯云 CLS、Google Cloud Logging 等；Kong 集成范围待核实。
- [ ] 错误日志集中收集与轮转：APISIX `error-log-logger`、`log-rotate`；Kong 对应部署方案。
- [ ] 节点状态、运行时诊断与健康接口：区分数据面接口与平台管理能力。
- [ ] 企业 APM：Kong AppDynamics 企业版等；逐项记录外部系统依赖。

### 9. 消息与 Serverless

- [ ] HTTP 触发 AWS Lambda、Azure Functions、OpenWhisk：两者对应插件。
- [ ] OpenFunction：APISIX `openfunction`；Kong 对应扩展待核实。
- [ ] 前置/后置自定义函数：Kong Pre/Post Function；APISIX Serverless Pre/Post Function。
- [ ] 请求写入 Kafka：Kong Kafka Upstream 企业版；APISIX Kafka PubSub 等能力。
- [ ] HTTP 消费 Kafka：Kong Kafka Consume 企业版；APISIX 按 PubSub 接口范围核实。
- [ ] Confluent/Solace 生产、消费与日志：Kong 企业版/合作伙伴插件；APISIX 集成待核实。
- [ ] Kafka 协议代理与 SASL 等参数：APISIX `kafka-proxy`；
  与 HTTP 写消息、消费消息及日志投递分别验收。

### 10. AI、LLM、MCP 与 Agent

- [ ] 统一模型供应商入口：Kong AI Proxy；APISIX `ai-proxy`。
- [ ] 多模型负载均衡、重试、回退、健康检查：Kong AI Proxy Advanced（AI 授权）；
  APISIX `ai-proxy-multi`。
- [ ] Token 计量与限流：Kong AI 授权插件；APISIX `ai-rate-limiting`。
- [ ] 系统提示词注入、参数化模板、规则允许/拒绝：两者 Prompt Decorator/Template/Guard。
- [ ] 语义话题限制、输出防护：Kong Semantic Prompt/Response Guard（AI 授权）；
  APISIX 对应防护范围待核实。
- [ ] 云内容安全与提示注入检测：Kong AWS/Azure/GCP/Lakera 等 AI 授权集成；
  APISIX AWS/阿里云/Lakera 等插件，实际检测依赖外部服务。
- [ ] AI 个人敏感信息脱敏：Kong AI PII Sanitizer（AI 授权）；APISIX 对应方案待核实。
- [ ] 提示词压缩：Kong AI Prompt Compressor（AI 授权）；APISIX 对应插件待核实。
- [ ] 检索增强与上下文注入：Kong AI RAG Injector（AI 授权）；APISIX `ai-rag`。
- [ ] LLM 缓存：Kong AI Semantic Cache（AI 授权）；APISIX `ai-cache`，核实语义范围。
- [ ] LLM 改写请求：Kong AI Request Transformer；APISIX `ai-request-rewrite`。
- [ ] LLM 改写响应：Kong AI Response Transformer；APISIX 对应方案待核实。
- [ ] 模型评估模型输出：Kong AI LLM as Judge（AI 授权）；APISIX 外部评测集成待核实。
- [ ] API 转 MCP Tools：Kong AI MCP Proxy（AI 授权）；APISIX `openapi-to-mcp`。
- [ ] MCP 代理、工具聚合与可观测性：Kong AI MCP Proxy（AI 授权）；
  APISIX 按具体插件能力核实。
- [ ] MCP OAuth2：Kong AI MCP OAuth2（AI 授权）；APISIX 认证组合需验证。
- [ ] SSE 到 stdio MCP 桥接：APISIX `mcp-bridge` 已弃用，不作为新部署推荐方案。
- [ ] A2A Agent 流量治理：Kong AI A2A Proxy（AI 授权）；APISIX 专用能力待核实。

### 11. API 平台、商业化与组织治理

- [ ] 调用者、凭证与分组管理：两者对应网关资源。
- [ ] API 文档发布、开发者门户：Kong Dev Portal 配套产品；APISIX 需外部平台。
- [ ] 开发者应用注册、API 申请与审批：Kong Dev Portal 对应能力；APISIX 需平台编排。
- [ ] 按客户订阅权益放行：Kong Entitlement Enforcement 商业能力；
  APISIX 认证、配额与外部订阅服务组合。
- [ ] API 调用量和 AI Token 用量计费：Kong Konnect Metering & Billing 授权附加能力；
  APISIX `lago` 向外部 Lago 上报事件，不等于内置账单和支付系统。
- [ ] 管理员 RBAC、审计与多团队权限：Kong 企业管理/Konnect；APISIX 需核实控制面及外部治理。
- [ ] 配置隔离与多租户：Kong Workspaces 等；APISIX 需规划资源、控制面及运行环境隔离。
- [ ] 多集群、多环境与 API 目录：Kong Konnect 配套；APISIX 自建或生态平台。

### 12. 部署、自动化与扩展

- [ ] 管理 API 动态更新路由、上游与插件：两者支持。
- [ ] 声明式配置与版本管理：Kong DB-less/decK；APISIX Standalone 等模式。
- [ ] 控制面/数据面分离：核对 Kong Hybrid 与 APISIX 对应部署模式。
- [ ] 容器与 Kubernetes 部署：两者支持。
- [ ] Kubernetes Ingress、Gateway API：各自 Controller，逐项确认资源和一致性支持范围。
- [ ] GitOps/CI/CD：Kong decK/Terraform/Kubernetes；APISIX 配置文件/Admin API/Kubernetes。
- [ ] 多云、混合云与托管数据面：区分自行部署与 Kong Konnect 托管能力。
- [ ] 密钥外置、配置加密与证书轮换：Kong Vault 等；APISIX Secret 等，核对版本边界。
- [ ] 自定义 Lua 插件：两者支持。
- [ ] 外部语言插件：Kong 按开发机制核实；APISIX Java/Go/Python Plugin Runner 等。
- [ ] Wasm 扩展：APISIX 有官方开发入口；Kong 按版本核实。
- [ ] 插件阶段、执行顺序与前后置扩展：两者分别核实，不假设跨阶段语义等价。

**每个场景的验收要求**：
1. 固定竞品版本、部署方式、授权和外部依赖，并保存可复现配置与官方来源。
2. 审计 Rut 当前实现与测试，先确认差距，再确定优先级和是否纳入实现范围。
3. 覆盖正常、拒绝、失败、超时、取消、关闭、资源回收及容量耗尽路径；涉及运行时的
   能力验证 io_uring/epoll 一致性及相关协议差异。
4. 验证跨功能组合：HEAD、HTTP/1.0、请求分帧、流式响应、重试、客户端断开、
   连接复用、鉴权后限流、缓存隔离、灰度与故障回退等，不能仅以插件同名判定等价。
5. 状态型能力明确 shard 归属、跨节点一致性、计量时机、容量失败及降级语义；
   不将当前 Cache 描述为精确共享状态。
6. 需要语言变更时遵守 Swift-exact or absent，同步 DESIGN、语言卡与测试。

**官方资料索引**（本次整理来源；实施前重新核实）：
- [Kong Gateway](https://developer.konghq.com/gateway/)、
  [插件目录及授权标签](https://developer.konghq.com/plugins/)、
  [路由](https://developer.konghq.com/gateway/entities/route/)、
  [负载均衡](https://developer.konghq.com/gateway/load-balancing/)。
- [Kong 认证](https://developer.konghq.com/gateway/authentication/)、
  [安全](https://developer.konghq.com/gateway/security/)、
  [限流](https://developer.konghq.com/gateway/rate-limiting/)、
  [Datakit](https://developer.konghq.com/plugins/datakit/)。
- [Kong AI Gateway](https://developer.konghq.com/ai-gateway/)、
  [MCP Proxy](https://developer.konghq.com/plugins/ai-mcp-proxy/)、
  [Dev Portal](https://developer.konghq.com/dev-portal/)。
- [APISIX 插件目录](https://apisix.apache.org/plugins/)、
  [路由及版本文档导航](https://apisix.apache.org/docs/apisix/terminology/route/)、
  [上游](https://apisix.apache.org/docs/apisix/terminology/upstream/)、
  [服务发现](https://apisix.apache.org/docs/apisix/discovery/)。
- [APISIX Stream Proxy](https://apisix.apache.org/docs/apisix/stream-proxy/)、
  [HTTP/3 限制](https://apisix.apache.org/docs/apisix/http3/)、
  [OIDC](https://apisix.apache.org/docs/apisix/plugins/openid-connect/)、
  [SAML](https://apisix.apache.org/docs/apisix/plugins/saml-auth/)、
  [OPA](https://apisix.apache.org/docs/apisix/plugins/opa/)。
- [APISIX 配额限流](https://apisix.apache.org/docs/apisix/plugins/limit-count/)、
  [OpenAPI 校验](https://apisix.apache.org/docs/apisix/plugins/oas-validator/)、
  [Body Transformer](https://apisix.apache.org/docs/apisix/plugins/body-transformer/)、
  [批量请求](https://apisix.apache.org/docs/apisix/plugins/batch-requests/)、
  [Workflow](https://apisix.apache.org/docs/apisix/plugins/workflow/)。
- [APISIX GraphQL 限流](https://apisix.apache.org/docs/apisix/plugins/graphql-limit-count/)、
  [GraphQL 缓存](https://apisix.apache.org/docs/apisix/plugins/graphql-proxy-cache/)、
  [OpenTelemetry](https://apisix.apache.org/docs/apisix/plugins/opentelemetry/)。
- [APISIX 多模型代理](https://apisix.apache.org/docs/apisix/plugins/ai-proxy-multi/)、
  [AI 缓存](https://apisix.apache.org/docs/apisix/plugins/ai-cache/)、
  [Lakera](https://apisix.apache.org/docs/apisix/plugins/ai-lakera-guard/)、
  [OpenAPI 转 MCP](https://apisix.apache.org/docs/apisix/plugins/openapi-to-mcp/)、
  [MCP Bridge 弃用说明](https://apisix.apache.org/docs/apisix/plugins/mcp-bridge/)。
- [APISIX Lago](https://apisix.apache.org/docs/apisix/plugins/lago/)、
  [部署模式](https://apisix.apache.org/docs/apisix/deployment-modes/)、
  [外部插件](https://apisix.apache.org/docs/apisix/external-plugin/)。

## Rut 全场景实现计划：统一使用 Rut（2026-10-16）

**用户目标**：实现以上 Kong / APISIX 场景。配置、认证授权、流量策略、转换编排、
协议适配逻辑及控制面服务统一使用 Rut，不要求用户编写其他语言插件。
本节为实施计划；未完成项不构成当前语言支持承诺。

### 架构边界与交付形式

- 复用现有 C++23 编译器/运行时作为执行底座，不把“全部用 Rut”解释为本轮重写
  编译器、内核 I/O、TLS 或密码库。底座只提供通用且有界的能力；场景策略放在
  `.rut` 模块中，不为每个竞品插件增加一个 C++ 专用实现。
- 不新增 Lua、Go、Python、Java、JavaScript 或 Wasm 插件运行环境，不以外语 FFI
  作为场景验收的必需条件。不依赖 LDAP-HTTP、Kafka-HTTP 等桥接进程冒充直接支持；
  需要原生协议时补齐 Rut 可用的二进制编解码与连接原语。
- 外部身份提供方、注册中心、消息集群、LLM、向量库、计费服务仍可作为业务端点，
  客户端适配与策略由 Rut 编写。外部服务不能被写成网关内置能力。
- 交付物为可导入的 Rut 标准模块、可运行场景示例、回归测试及配置/部署文档；
  模块目录与公开 API 在基线审计后确定，以下模块分层不是新语法。
- 使用既有函数、结构、泛型、`import`、`chain` 等机制。确需语言扩展时先写语义与
  资源模型，遵守 Swift-exact or absent，更新 DESIGN、语言卡及测试。
- 140 项逐条保留，不用删除难项实现“全覆盖”。协议、门户和控制面等超出现有
  DESIGN 范围的工作进入明确的范围修订阶段，再进入实现。

### M0：建立可执行基线与逐项映射

- [ ] 为上节 140 项建立稳定编号及对应表，记录：Rut 当前入口、实现文件、现有测试、
  缺口、所属阶段、外部服务依赖、验收用例和状态。复合项目拆分子场景，保留原条目映射。
- [ ] 逐项编译/运行最小示例；区分已实现、部分实现、仅设计、缺失，不凭文档示例推定支持。
- [ ] 校正 DESIGN §3.10 的覆盖表：去除与当前实现不符的 Fully Covered 声明，
  把旧头字段赋值等写法与语言卡同步；原来的 Out of Scope 改为本计划的后续范围。
- [ ] 给每个场景记录可复现的竞品基线与差异，不把功能名称相同视为语义相同。
- [ ] 固定每批验收环境、数据集及功能关闭基线；记录吞吐、延迟、内存、连接和状态容量。

**完成条件**：140 项都有落点和证据；当前支持状态与语言卡一致，设计项不混入已实现项。

### M1：补齐 Rut 可组合的通用原语

后续模块依赖此阶段；每个原语独立审阅和落地，不新增大而全的网关关键字。

- [ ] 有界数组/集合、字节视图、整数/字节序转换、解析结果、字符串与数值转换；
  支持重复 header/query 值、有限遍历和实际需要的泛型组合。
- [ ] 类型化及动态 JSON 解析/序列化；明确字段缺失、重复键、深度、大小与错误语义。
- [ ] 请求体、响应体/状态的有界读写；补齐跨异步暂停的 stream-owned Response 与
  `chain before/after`，保留分支效果提交语义。
- [ ] Rut 可用的流读写、背压、计时、并发提交、取消与结构化清理；明确连接断开、
  部分读写、取消竞态及热更新时的对象生命周期。
- [ ] 严格有界状态表和 owner-shard 原子更新；容量耗尽显式失败；TTL、LRU 缓存
  与严格会话/并发计数分离。跨 shard 通过消息传递，不使用 Cache 替代精确状态。
- [ ] 单调计时与墙钟分离，定义时间跳变处理；安全随机数、常量时间比较、密钥句柄、
  签名/验签与证书信息等通用安全接口复用已有受审计实现，不用 Rut 手写密码算法。
- [ ] 将现有底座的能力逐项暴露给 Rut：地址/DNS、TLS、连接池、指标、日志、
  配置快照、RCU 热更新；缺失能力单独补齐而非用外语插件绕过。

**完成条件**：原语有资源上限、错误与取消语义；编译器/JIT/运行时测试覆盖，
`rut_runtime` 保持不依赖 LLVM，无额外插件语言运行环境。

### M2：基础入口与日常流量策略（清单 1、2、4、6）

- [ ] 将已有 HTTP/HTTPS、HTTP/2、WebSocket 能力接入统一 Rut 场景入口并补齐差距。
- [ ] Rut 模块实现 Host/路径/方法/header/query 条件路由、版本路由、重写、重定向、
  固定响应、维护页、CORS、IP/CIDR/URI/UA/Referer 规则及请求 ID。
- [ ] 支持有界请求读取与实际接收字节限制，不能只检查 Content-Length；
  明确 chunked、HTTP/2 DATA、解压后大小等适用边界。
- [ ] Rut 模块实现流量标签、用户稳定分桶、蓝绿、灰度、镜像、Mock、延迟与故障注入。
- [ ] 镜像请求设独立容量、超时和敏感信息策略；主请求不被慢镜像无限阻塞。

**完成条件**：所有模块有可运行 `.rut` 示例，覆盖匹配优先级、拒绝、取消和组合路径；
对 HTTP/1.0、HEAD、HTTP/2、流式传输分别验证。

### M3：状态、限流与高可用（清单 2、5、7）

- [x] 转发点显式负载均衡：`forward(api, load_balance: .roundRobin)` /
  `.leastRequests`；参数必填，单后端无例外，无默认/继承；轮询游标按转发点和 shard
  隔离，计数在共享 upstream 的路由间共享；迁移 helper、示例和测试。

- [ ] 用 Rut 实现固定/滑动窗口、GCRA/漏桶、突发、并发配额、响应计量与服务整体额度。
- [ ] 明确每次尝试/仅接收/实际消耗的扣费时机，取消时并发计数只释放一次。
- [ ] 先交付精确单节点 owner-shard 语义，再实现跨节点协议与一致性策略；
  远端状态故障必须显式选择拒绝、降级或本地额度，不能静默放大限额。
- [ ] 用 Rut 实现健康策略、熔断、恢复探测、重试与回退；底座只提供通用连接与调度能力。
- [ ] 仅在可证明安全时重试非幂等/已部分发送请求；限制重试预算，避免重试风暴。
- [ ] 用 Rut 实现 HTTP 缓存键、TTL、失效、Vary、权限隔离、合并回源及 stale 策略；
  存储、压缩/解压作为通用能力，设置大小、CPU 与膨胀上限。

**完成条件**：确定性时间与容量测试、跨 shard 竞争测试和故障恢复测试通过；
清楚区分近似限流、精确配额、可丢失缓存及不可丢失业务状态。

### M4：身份、安全与企业访问（清单 3、4）

- [ ] 先以 Rut 模块交付 API Key、Basic、HMAC、JWT/JWE、ACL、外部授权、Webhook 校验。
- [ ] 补齐 OIDC/OAuth2 内省、会话、密钥/JWKS 轮转、上游 Token、CAS、SAML 与
  Keycloak/Casdoor/OPA/Casbin/Wolf 协议适配；区分认证、授权及身份提供方职责。
- [ ] LDAP 直接接入用 Rut 协议模块实现，不以 HTTP 桥接作为完成条件。
- [ ] 客户端证书映射、mTLS 授权、ACME、OCSP 与证书轮转策略使用 Rut；
  TLS/证书密码操作继续使用底座的受审计原语。
- [ ] 用 Rut 实现 JSON Schema/OpenAPI 校验、CSRF、结构威胁限制和基础注入规则；
  明确规则覆盖，不宣称通用正则等价于完整 WAF。
- [ ] 外部 WAF/WAAP、内容检测服务通过 Rut 客户端集成；记录外部服务不可用时策略。
- [ ] SAML/XML 等解析器使用有界数据模型，禁用危险外部实体，覆盖重放、签名包装、
  解析差异与畸形输入；安全协议采用标准测试向量和负面测试。

**完成条件**：身份绕过、重放、密钥轮转、时钟偏差、凭证泄露及故障策略均有测试；
完整登录协议不能以“能发送一次 HTTP 请求”替代。

### M5：转换、编排与可观测性（清单 6、8）

- [ ] Rut 模块实现请求/响应结构转换、JSON/XML 模板、错误转换及数据脱敏。
- [ ] Rut 实现批量请求、受限并发聚合、Callout 与条件流程；定义结果顺序、
  部分失败、总超时、取消、请求扇出和内存上限。
- [ ] Rut 模块实现指标标签、结构日志、请求关联、追踪上下文传播、采样与导出策略。
- [ ] Rut 客户端直连 HTTP/TCP/UDP/Syslog/OTLP 等端点；Kafka/RocketMQ 等复用 M7
  协议模块，不把发往 HTTP 收集器视为原生协议投递。
- [ ] 日志/追踪导出设批量、队列上限、脱敏及丢弃计数；定义指标基数与故障隔离。
- [ ] 核实 Prometheus、Datadog、StatsD、Zipkin、SkyWalking、APM、云日志及搜索/分析
  平台的线协议，逐一形成 Rut 适配模块与兼容测试。

**完成条件**：慢/失效导出端不耗尽网关资源；每种声明支持的目标都有协议兼容证据。

### M6：gRPC、GraphQL 与 WebSocket 消息治理（清单 1、5、6、7）

- [ ] 补齐 HTTP/2 上下游及 gRPC metadata、trailers、状态、deadline、取消与流式语义。
- [ ] 在通用字节/流能力上实现 Rut protobuf 编解码模块、描述符读取与 HTTP/gRPC 转码；
  不强制用户用其他语言生成或维护插件。
- [ ] Rut 实现 gRPC-Web 文本/二进制 framing 与 trailers，覆盖浏览器跨域与流式限制。
- [ ] Rut 实现 GraphQL AST、变量/操作解析、成本计算、限流、缓存与 REST/GraphQL
  双向适配；mutation、订阅、错误与 schema 变更分别定义边界。
- [ ] Rut 实现 WebSocket 消息限制、校验与转换；覆盖分片、控制帧、UTF-8、压缩及取消。

**完成条件**：真实客户端/服务端互通、畸形帧、部分写入及取消测试通过；
不能以 HTTP/2 透传宣称完成 gRPC 转码或消息治理。

### M7：L4、自定义协议、注册中心与 Serverless（清单 1、2、9）

- [ ] 修订现有 L7-only 范围，设计 Rut 可编程 TCP/UDP 入口、会话与报文生命周期；
  底座维持函数指针回调和后端一致性，不引入协程或虚分派。
- [ ] Rut 实现 DNS/Consul/Nacos/Eureka/Kubernetes 等发现适配，定义更新版本、
  失联缓存、TTL、抖动和 RCU 发布语义。
- [ ] Rut 协议模块实现 MQTT client_id 解析与分流、Dubbo 编解码/转码、Kafka 生产/消费/
  协议代理及相关认证，按协议逐批交付。
- [ ] 为 RocketMQ、Confluent、Solace 及所需状态后端实现 Rut 客户端适配；
  同步确认其握手、认证、确认/重试、消息顺序与重复投递语义。
- [ ] Rut 实现 AWS Lambda、Azure Functions、OpenWhisk、OpenFunction 客户端、
  签名认证、超时、错误映射与流式响应处理。
- [ ] HTTP/3/QUIC 单列协议工程：先评估现有底座与依赖约束，再设计 Rut 暴露面；
  不承诺用普通 UDP 脚本重写 QUIC/TLS 即可满足生产要求。

**完成条件**：每个协议独立互通、模糊测试及资源上限测试通过；
消息代理、HTTP 消息 API 与日志投递分别验收。

### M8：AI、RAG、MCP 与 Agent（清单 10，依赖 M3–M6）

- [ ] Rut 实现模型供应商适配、统一 API、凭证选择、流式 SSE 转换与错误映射。
- [ ] Rut 实现模型路由、健康检查、重试/回退、Token 计量与预算；定义流式中途失败、
  已消耗但未返回 Token、客户端取消与供应商用量缺失的结算语义。
- [ ] Rut 实现提示词注入/模板/规则防护、请求/响应改写、敏感数据脱敏与压缩流程。
- [ ] Rut 实现云 Guardrail/Lakera/内容安全及 LLM-as-Judge 客户端；
  语义检测和模型评判依赖相应模型/服务，不以简单字符串匹配冒充。
- [ ] Rut 实现向量检索/RAG、语义缓存与语义话题限制；处理租户隔离、检索权限、
  提示注入、缓存投毒及向量模型版本变化。
- [ ] Rut 实现 OpenAPI 到 MCP Tools、MCP 代理/聚合、协议版本协商、OAuth2、
  Streamable HTTP/SSE 和 A2A 治理。
- [ ] 对弃用的 stdio MCP Bridge 场景单列兼容性决定；若保留，用 Rut 调用受限进程
  能力，先明确命令白名单、权限、配额、取消和隔离，不能让网关执行任意命令。

**完成条件**：有协议回放和供应商 mock 测试，再做真实端点互通；
流式、预算、安全、工具权限与资源耗尽均有负面用例。

### M9：Rut 控制面、门户与商业化（清单 11、12）

- [ ] 用 Rut HTTP 服务实现管理 API、资源模型、配置校验、版本快照、发布与回滚；
  写入一致性和持久化先定义，不把本地缓存当作配置数据库。
- [ ] 用 Rut 实现管理员认证、RBAC、审计、多团队/租户隔离、环境与集群管理；
  明确配置隔离不等于进程或资源隔离。
- [ ] 用 Rut 实现 API 目录、OpenAPI 文档、开发者应用注册、凭证签发、申请审批和订阅权益。
- [ ] 门户优先使用 Rut 服务端生成 HTML/CSS；交互通过 HTTP 表单和服务端渲染完成，
  不要求引入 JavaScript 应用或另一种插件语言。
- [ ] 用 Rut 实现用量事件、Lago/其他计费端点适配、额度与权益执行；完整账单/
  结算若纳入范围，需另定义持久账本、幂等、重放与对账，不使用 lossy Cache。
- [ ] 用 Rut 实现声明式配置导入/导出、变更计划、GitOps 发布接口和密钥服务适配。
- [ ] Kubernetes Ingress/Gateway API 控制器使用 Rut 实现 watch/reconcile；
  通过对应版本 conformance 测试后才声明兼容。
- [ ] 自定义功能统一走 Rut 模块与同一编译链，不建设多语言 Plugin Runner；
  Kong/APISIX 的外语 SDK/Wasm 对标项以 Rut 扩展能力和隔离验收替代，不承诺二进制兼容。

**完成条件**：权限、审计、备份恢复、发布回滚、断连重连与热更新测试通过；
API、页面及运维流程均不依赖用户维护其他语言代码。

### 依赖、批次与推进顺序

| 顺序 | 阶段 | 前置条件 | 可评审交付 |
|---|---|---|---|
| 1 | M0 基线 | 当前代码/测试 | 140 项映射、状态纠偏、优先级 |
| 2 | M1 通用原语 | M0 | 小批原语、语义文档、聚焦测试 |
| 3 | M2 基础策略 | M1 所需子集 | 最早可运行的 Rut 标准模块与示例 |
| 4 | M3 状态与 HA | M1 状态/异步能力 | 精确配额、熔断、缓存模块 |
| 5 | M4 身份安全 | M1/M3 | 认证/授权/证书与校验模块 |
| 6 | M5 编排与观测 | M1；复用 M3/M4 | 编排、日志、指标、追踪模块 |
| 7 | M6 协议治理 | M1–M5 所需子集 | gRPC/GraphQL/WS 消息模块 |
| 8 | M7 其他协议 | M1/M3/M4；先完成范围修订 | 每种协议独立模块与兼容证据 |
| 9 | M8 AI/Agent | M3–M6；复用已交付协议 | 模型/RAG/MCP/A2A 模块 |
| 10 | M9 平台 | M3/M4/M5；所需持久化能力 | Rut 管理服务、门户、计费与控制器 |

M5 的消息日志适配等待 M7 对应协议；M9 的资源模型设计可提前，但实现依赖不能绕过。
不按大阶段提交巨型 PR：每批只完成一个原语或一组紧密相关的 Rut 场景，包含实例与证据。
先交付基础 HTTP 策略，再扩展协议与平台；尚未评估的工作不填写虚假工期。

### 第一批具体工作（计划就绪后的实施入口）

- [ ] M0：为 140 项生成编号与实现/测试映射，先核实 header/query、多值集合、
  JSON、响应中间件、异步清理、严格状态、密码接口和 HTTP/2 上游的真实状态。
- [ ] 形成 M1 最小原语设计，明确已有实现可复用部分与必要缺口，不先新增语法。
- [ ] 选择已有能力可支撑的请求 ID、访问规则、CORS、维护响应及条件分流，
  交付第一组纯 Rut 模块；若存在原语缺口，先完成对应原语批次再发布示例。
- [ ] 每批更新本计划与 140 项映射；只有编译、执行和验收证据齐备才勾选完成。

**统一发布门槛**：聚焦编译器/JIT/运行时测试、受影响后端与协议互通测试、格式与
静态检查；底座改动保持无 C++ 标准库链接约束、热路径无堆分配与 shard 归属。
安全协议需标准测试向量，二进制解析需畸形输入/模糊测试；文档示例纳入编译执行验证。
