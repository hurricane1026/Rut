# 完全替换 Envoy：缺口与实施顺序

审计日期：2026-09-28。代码基线：`main` 的 `e18a4838`（#727、#728 已合并）。
对照版本：仓库固定的 Envoy v1.39.1；不把 `latest` 的新增能力算入本次基线。
本报告是代码审计、官方文档比对和一次本地运行复现，未宣称完成全协议差分审计。

## 结论与边界

目前完成的是受限 HTTP/1.1 静态代理子集，距离无条件替换 Envoy 仍有明显差距。
“手写 `.rut` 能实现某个功能”“helper 能接受某种 Envoy 配置”“线上行为等价”是三个验收条件。
它们需要分别验证，不能用生成文本正确或单个测试任务通过替代。

- **Rut 语言与运行时**：实现协议、路由、超时、连接池、安全与资源生命周期。
- **同仓库 helper**：将支持的 Envoy 配置映射为普通 `.rut`；不能在 helper 中补运行时行为。
- **控制面适配器**：未来可独立实现 xDS 接入，再通过 Rut 的配置更新接口发布；不把 Envoy 配置解析嵌回网关主程序。
- **测试系统**：同一输入比较两端实际转发、回复、连接关闭、超时和资源回收行为。

完整 Envoy 还包含控制面、运维接口和扩展生态。若目标是任意现有部署无改动替换，这些也是工作范围；
若目标是指定业务代理，应以真实配置和流量特征定义验收集合。没有这个集合，不给“完成百分比”或工期承诺。

## 已有能力：不应重复建设

#728 已整合请求策略、响应顺序与小写头、Date 保留、canonical reason、本地回复布局和 503 连接失败回复。
Envoy helper 已独立到 [`helpers/envoy/`](../helpers/envoy/README.md)，可不依赖 LLVM/运行时库单独构建。
当前 Envoy 实际成对差分 CI 已通过（run `36416010559`）；范围见下文。

Rut 自身也已有 TLS 服务端、HTTP/2 连接实现、WebSocket、普通转发的多种 body framing、
HTTP/1 连接池、多后端 round-robin、被动健康状态、并发上限、部分主动健康检查、限流、指标、日志和配置热更新基础。
这些基础不能自动证明与 Envoy 策略组合后兼容，也不能自动证明 Envoy 的同名功能已完全实现。

关键依据：
[`language-card`](language-card.md)、[`tls.h`](../include/rut/runtime/tls.h)、
[`http2_conn.h`](../include/rut/runtime/http2_conn.h)、
[`upstream_pool.h`](../include/rut/runtime/upstream_pool.h)、
[`route_table.h`](../include/rut/runtime/route_table.h)、
[`callbacks_impl.h`](../include/rut/runtime/callbacks_impl.h)。

## 1. P0：路由正确性，先于扩展覆盖面

### 已在当前二进制复现的错误

临时 `.rut`：

```swift
listen 127.0.0.1:PORT
route GET "/" { return 200 }
route GET "/api" { return 201 }
```

启动 `build/src/rut <file> --shards 1 --no-pin`，逐条发送 HTTP/1 请求：

| 请求 | 实际状态 | 按 Rut 分段路由契约应得 |
| --- | --- | --- |
| `/` | 200 | 200 |
| `/api` | 201 | 201 |
| `/api/x` | 201 | 201 |
| `/apifoo` | **201** | **200** |

复现进程和临时文件已清理；这不是 Docker Envoy 现场对照。
根因已进一步定位为 ART 在终端节点缺少分段边界检查；不仅 root + `/api`，
单独注册 `/api` 也会误匹配 `/apifoo`。本次修复使生产 `RouteConfig` 的 ART 显式采用
分段前缀匹配，并同步修复其 JIT 特化；底层 BytePrefix 模式保留供独立使用。
回归包含普通/JIT 路由、节点扩容、手写 `.rut` 真实进程与两个真实上游的 helper 输出执行。
Envoy 多路由成对差分已注册 CI；其结果以该 PR 的 CI 为准。
百分号编码、重复斜杠和两种后端的完整矩阵仍属于后续 P0 验收，不因本次边界修复而宣称完成。

**验收**：真实进程、实际派发引擎、两种 Linux I/O 后端覆盖 root/前缀/exact/同前缀非分段路径。
再覆盖双斜杠、百分号编码、原始路径与规范化路径、查询串；比较实际被联系的上游，而不只比较最终状态码。

## 2. 缺口清单与归属

以下是工作包，不是声称某模块完全不存在。P1/P2 为建议实施顺序；具体部署依赖的能力可提升优先级。

| 优先级 | 工作包 | 当前证据和限制 | 应补在哪一层 |
| --- | --- | --- | --- |
| P1 | H1 请求流式语义 | ID4 保留 Host 策略仍要求固定长度 body 在接收缓冲内物化；chunked、有效 Expect、upgrade 等形态受限。普通转发已有能力不能直接用于该策略 | Rut 请求 body/头策略与运行时组合 |
| P1 | H1 响应完整性 | `build_upstream_order_response_headers` 明确拒绝 204/205/304、非 H1.1、无单一 Content-Length、chunked；还需 1xx、trailers、close-delimited 与升级的完整语义 | Rut 响应 framing、状态分类、流式生命周期 |
| P1 | 头语义与容量 | 请求/响应头数量固定上限 64；部分重复 inline 头直接拒绝，而 Envoy 会合并。还需精确处理重复字段、OWS、大小限制、透传与删除顺序 | Rut 类型化头操作和解析器 |
| P1 | 完整超时与失败分类 | helper 要求 route timeout 显式为 `0s`，非零值不支持；运行时仍有默认 30s 上游超时。`header_order: .upstream` 不能组合当前严格 response-read-timeout/buffering/timeout-failure 方案 | Rut 连接、首字节、整请求、空闲、每次尝试的超时模型 |
| P1/P2 | TLS、HTTP/2、gRPC、HTTP/3 | Rut 已有 TLS/H2 基础，但 ID4 与 Envoy H1 策略有 cleartext/H1 限制；未发现可直接作为 Envoy 替代的完整上游 H2/gRPC、mTLS/动态证书、QUIC/H3 链路 | Rut 协议/连接/证书能力；helper 只映射 |
| P2 | 路由表达力 | helper 只接受有限的 exact 和以 `/` 结尾的 prefix；无 header/regex 等完整匹配、多 vhost 域名、完整 rewrite/weighted route 支持，部分无 catch-all 配置无法生成 | 先定义 Rut 的 raw-prefix、exact、规范化和优先序语义；再扩 helper |
| P2 | direct response 与 redirect | helper 已解析模型，但 `validate()` 仍返回 `direct_response is not lowered yet` / `redirect is not lowered yet`。Rut 已有 local_response/redirect，需逐项核对布局、状态、body、Location/query/authority 后映射 | 已有 Rut 能力复用；不足之处先补语言/运行时，再补映射 |
| P2 | 集群与弹性 | Rut 有 RR、连接池、max_inflight 和固定阈值被动摘除；不等于 Envoy 可配置 LB、priority/locality、DNS/EDS、outlier detection、重试条件/预算/退避、hedging。主动探测 `io_uring::kSupportsHealthProbe == false`，epoll/kqueue 为 true | Rut 类型化 upstream、调度、重放与资源预算模型 |
| P2 | 容量与组合约束 | helper 上限 8 routes、8 clusters，每 cluster 单 IPv4 endpoint；匹配文本上限 64 bytes；编译器 token 上限 4096，生成重复策略会提前撞限 | helper 容量和 Rut 编译器表示/预算；不能仅调大数字 |
| P3 | 动态控制面 | 静态 helper 明确不负责 xDS。仓库审计未发现可运行的完整 ADS/CDS/EDS/LDS/RDS/SDS/Delta 接入；RCU 热更新基础不等于资源版本、依赖、ACK/NACK 与断线恢复 | 独立控制面适配器 + Rut 配置发布契约 |
| P3 | 安全与过滤器 | 完整 JWT/JWKS、ext_authz、RBAC、全局限流协议、故障注入、Wasm/Lua/动态扩展兼容没有现成完整映射；有 middleware/本地限流不代表这些语义齐全 | Rut 通用 middleware/异步调用/安全原语，必要时独立适配器 |
| P3 | 运维与可观测性 | 有日志/metrics/drain/reload 基础，但 Envoy admin、stats 名称、日志格式、追踪传播、response flags/details、过载管理及部署控制面契约尚未对齐 | Rut 可观测性/运维接口，兼容展示可放适配层 |

### 已核对的直接代码依据

- H1 请求 admission / `inspect_request_policy_body`、inline 头去重限制：[`callbacks_impl.h`](../include/rut/runtime/callbacks_impl.h)。
- H1 响应拒绝集合：同文件 `build_upstream_order_response_headers`。
- Envoy 布局不能叠加现有读取超时与 buffering：[`language-card.md`](language-card.md) 的 upstream header order 策略说明及编译器校验。
- 默认 30s：[`epoll_event_loop.h`](../include/rut/runtime/epoll_event_loop.h)、[`iouring_event_loop.h`](../include/rut/runtime/iouring_event_loop.h) 的 `kDefaultUpstreamTimeout`。
- 主动健康检查支持差异：epoll/io_uring/kqueue 对 `kSupportsHealthProbe` 的实际定义，优先于部分过时的“data only”注释。
- 静态配置限制与拒绝：[`helper parser`](../helpers/envoy/include/rut/envoy/parser.h)、[`helper converter`](../helpers/envoy/converter.cc)。
- token 预算：[`lexer.h`](../include/rut/compiler/lexer.h)；64 个头字段：[`http_parser.h`](../include/rut/runtime/http_parser.h)。

## 3. 差分测试距离完整替换还有多远

[`kAssertedCaseNames`](../tests/test_envoy_differential.cc) 当前只有 9 个强制比较场景：

`get_smoke`、`get_upstream_date_server`、`get_client_close`、`head_smoke`、`post_fixed`、
`connect_failure`、`get_hop_by_hop`、`trace`、`options_star`。

`connect_authority` 和三类 forged-header 场景仍是 record-only，不影响验收退出码。
最后一种客户端 `X-Envoy-External-Address` 的无条件删除还是有意行为差异；完整替换需要明确决定保留差异、
提供通用可配置策略，还是限制兼容声明。不能悄悄将记录成功提升为语义等价。

缺少的验收维度：

1. 多路由/多集群的真实请求分发、无路由回退、所有优先序与路径边界。
2. TLS/H2/gRPC、流式 body/trailer、长连接、100/103/204/304、取消/复位/半关闭。
3. connect refused、connect timeout、已连接后 reset、协议错误、头/body 超时的状态和正文差异。
4. 大 body、多头、大头、重复头、异常但合法 HTTP、流水线、背压及资源预算边界。
5. 热更新期间的连接/证书/上游变更；健康检查与多后端故障；epoll/io_uring 一致性。
6. 持续负载与长稳运行；不同 Envoy 配置的性能和资源上限，而非单个吞吐 benchmark。

验收应同时比较：下游结果、上游实际收到的数据/被选 endpoint、是否不应联系上游、连接关闭时机、超时边界和资源归还。
安全拒绝与 Envoy 接受不同，仍属于兼容缺口；它只能缩小支持范围，不能被计为支持。

## 4. 建议的实施次序

1. **先修 P0 路由分发，并加入真实多路由差分。** 防止规则或上游选择错误。
2. **完成普通 H1 静态代理闭环。** 请求/响应 streaming、状态/头边界、完整超时和失败分类。
3. **扩展类型化路由/upstream 与组合能力。** TLS/H2、direct response、redirect、匹配/重写、LB/重试；helper 随后映射。
4. **完善生产运行契约。** 各后端健康检查、热更新、证书、日志/指标/追踪、容量和长稳验证。
5. **按替换场景补控制面与扩展生态。** service mesh 使用场景中的 xDS、mTLS、授权应前移为上线前置条件。

每个工作包采用“Rut 语义/枚举及组合规则 → 编译链 → 运行时 → 手写 `.rut` 测试 → helper 映射 → Envoy 差分”的顺序。
新增字段名或成员仅是设计提案，必须遵守 Swift-exact or absent 和现有关键字约束；本报告没有新增任何语言语法。

## 5. 本次核查排除的旧结论

- 请求/响应/本地回复能力未进 main：已经过时，#728 已整合。
- 上游空 reason phrase 一定被拒绝：对新的 upstream-order 布局不成立，当前实现明确允许并规范化。
- 所有 Location/Last-Modified 等头都被旧严格布局拒绝：不能直接套用到新的 upstream-order 路径。
- Rut 完全没有 TLS、HTTP/2、LB、健康检查、限流或热更新：不成立，应审计覆盖和组合限制。
- `direct_response`/`redirect` 的 helper 未实现就表示 Rut 没有本地回复/重定向：不成立。

## 官方参照（Envoy v1.39.1）

- [架构能力范围](https://www.envoyproxy.io/docs/envoy/v1.39.1/intro/arch_overview/arch_overview)：协议、集群、安全、可观测性、控制面、扩展生态。
- [HTTP routing](https://www.envoyproxy.io/docs/envoy/v1.39.1/intro/arch_overview/http/http_routing)：匹配/重写、weighted routing、timeout/retry/hedging、直接回复等对照范围。
- [xDS](https://www.envoyproxy.io/docs/envoy/v1.39.1/intro/arch_overview/operations/dynamic_configuration)：动态资源及 ADS/Delta，作为控制面验收参照。
- [TLS](https://www.envoyproxy.io/docs/envoy/v1.39.1/intro/arch_overview/security/ssl)：双向 TLS、证书验证、ALPN/SNI 等对照范围。
- [Load balancing](https://www.envoyproxy.io/docs/envoy/v1.39.1/intro/arch_overview/upstream/load_balancing/overview)：集群弹性与负载均衡能力参照。
