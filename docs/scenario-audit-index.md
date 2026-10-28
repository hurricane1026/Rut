# 场景审计索引（M0）

基线：`f80f07cb02f6fc95e90ad16e4334e622249bd8e4`。来源是 [TODO.md 的 Kong / APISIX 场景清单](../TODO.md)。本索引只固定现有 140 项的标识；编号不代表功能完成，也不代表竞品对照已验证。

编号一旦分配不得重排或复用；原条目拆分时保留原编号，使用后缀标识子场景。TODO 清单变化时同步更新本表。除下文有证据的项目外，所有条目均为**待审计**。竞品版本、部署方式、授权和实际差分都尚待确定。

## 清单

### 1. 流量入口与协议

- **K001** REST API 统一入口、HTTP/HTTPS 反向代理：两者支持。
- **K002** HTTP/2、gRPC 服务入口：两者支持。
- **K003** 浏览器 gRPC-Web：Kong gRPC-Web；APISIX `grpc-web`。
- **K004** HTTP/JSON 到 gRPC 转码：Kong gRPC-Gateway；APISIX `grpc-transcode`。
- **K005** WebSocket 长连接代理：两者支持。
- **K006** WebSocket 逐消息大小限制与内容校验：Kong 专用企业版插件；APISIX 对应范围待核实。
- **K007** SSE、流式接口：两者可承载；需逐项验证缓冲、超时与客户端取消。
- **K008** TCP/UDP 四层代理：Kong 协议路由；APISIX Stream Proxy。
- **K009** TLS 终止、SNI 分流及 TLS 透传：核对两者对应路由与 Stream 配置。
- **K010** HTTP/3/QUIC：APISIX 文档标为实验性下游支持、不支持 HTTP/3 上游， 不建议生产使用；Kong 对应范围待核实。
- **K011** MQTT 按 client_id 分流：APISIX `mqtt-proxy`，仅 Stream 模式；Kong 对应插件待核实。
- **K012** HTTP 到 Dubbo：APISIX `dubbo-proxy`、`http-dubbo`；Kong 需核实扩展方案。
### 2. 路由、服务发现与高可用

- **K013** Host 多域名、路径、请求方法路由：两者支持。
- **K014** 请求头、查询条件与表达式路由：核对 Kong 路由表达式与 APISIX 路由变量能力。
- **K015** API 多版本共存：通过 Route/Service 等资源组织。
- **K016** URL 前缀剥离、Host/URI 重写：路由配置与转换插件。
- **K017** 多实例与加权负载均衡：Kong Upstream/Target；APISIX Upstream。
- **K018** 根据客户端或请求属性进行哈希、保持后端选择：核实具体算法与会话语义。
- **K019** 主动健康检查、被动失败检测、故障摘除与恢复：两者支持对应机制。
- **K020** 上游连接/读写超时与重试：验证重试条件、次数及非幂等请求边界。
- **K021** DNS 服务发现：两者支持。
- **K022** 注册中心发现：APISIX DNS、Consul、Nacos、Eureka、Kubernetes 等； Kong 按具体集成核实。
- **K023** 蓝绿、金丝雀发布：Kong Canary Release 企业版等方案；APISIX `traffic-split`。
- **K024** 按用户或请求条件灰度：路由、流量标签及分流策略组合。
- **K025** 镜像与影子流量：APISIX `proxy-mirror`；Kong 直接对应方案待核实。
- **K026** 健康熔断与 API 熔断：Kong 健康检查/熔断；APISIX 健康检查及 `api-breaker`。
### 3. 身份认证与授权

- **K027** API Key、Basic、JWT、HMAC：两者有对应认证插件。
- **K028** LDAP 企业目录：Kong LDAP/企业版高级插件；APISIX LDAP 及版本相关高级插件。
- **K029** OIDC 单点登录、OAuth2 Token 内省：Kong 对应企业版插件；APISIX `openid-connect`。
- **K030** 网关 OAuth2 认证端点：Kong OAuth2 Authentication；APISIX 通常接外部 IdP。
- **K031** SAML 单点登录：Kong SAML 企业版；APISIX `saml-auth`。
- **K032** CAS、Keycloak、Casdoor：APISIX 专用插件/OIDC；Kong 按协议或扩展方案核实。
- **K033** 多种认证共存与匿名回退策略：Kong 插件组合；APISIX `multi-auth`。
- **K034** Consumer、分组及 API 访问范围：Kong Consumer/ACL；APISIX Consumer/Group/限制插件。
- **K035** OPA 策略授权：Kong 企业版；APISIX `opa`，策略引擎为外部服务。
- **K036** Casbin/Wolf RBAC：APISIX `authz-casbin`、`wolf-rbac`；Kong 集成方案待核实。
- **K037** 外部认证委托：APISIX `forward-auth`；Kong 对应调用或扩展方案待核实。
- **K038** JWE 解密：Kong 企业版；APISIX `jwe-decrypt`。
- **K039** JWT 验签与重新签发：Kong JWT Signer 企业版；APISIX 对应范围待核实。
- **K040** 获取访问上游所需 OAuth Token：Kong Upstream OAuth 企业版；APISIX 方案待核实。
- **K041** 客户端证书认证：Kong mTLS Authentication 企业版；APISIX mTLS 配置。 分别审计双向 TLS 握手、证书身份映射与 API 授权。
- **K042** 身份会话管理、凭证轮转及跨网关身份复用：区分插件会话与 Kong Identity 等平台能力。
### 4. 安全与输入校验

- **K043** CORS、IP 白/黑名单：两者有对应插件。
- **K044** URI、User-Agent、Referer 规则拦截：APISIX 专用插件；Kong Bot Detection/路由/扩展组合。
- **K045** Consumer 访问限制与 ACL：两者对应资源与插件。
- **K046** CSRF：APISIX `csrf`；Kong 集成方案待核实。
- **K047** 请求体大小限制：Kong Request Size Limiting；APISIX `client-control` 等。
- **K048** 请求字段与结构校验：Kong Request Validator 企业版；APISIX `request-validation`。
- **K049** OpenAPI 请求校验：Kong OAS Validation 企业版；APISIX `oas-validator`。
- **K050** OpenAPI 响应校验：Kong OAS Validation 企业版；APISIX 版本支持范围待核实。
- **K051** JSON/XML 结构、深度与大小防护：Kong 专用企业版插件；APISIX 需核实组合或外部方案。
- **K052** 注入攻击与 Bot 防护：Kong Injection Protection 企业版/Bot Detection； APISIX 规则与 WAF 集成方案。
- **K053** WAF/WAAP/API 安全集成：Kong 第三方插件；APISIX `chaitin-waf` 接 SafeLine 等。 不将连接器描述为内置完整 WAF。
- **K054** Webhook 签名规范验证：Kong Standard Webhooks；APISIX 对应方案待核实。
- **K055** TLS 证书、自动签发/轮换、OCSP、握手与证书元数据：逐项核实配置与插件； Kong 有 ACME 及部分企业版 TLS 插件，APISIX 有 OCSP/国密相关能力。
- **K056** 敏感数据脱敏：区分请求、响应、访问日志与 AI 内容，核实对应版本插件范围。
### 5. 限流、配额与服务保护

- **K057** 按 API、Consumer、IP 等维度限流：Kong Rate Limiting；APISIX 限流插件与键配置。
- **K058** 周期调用配额与多个限制窗口：Kong Rate Limiting；APISIX `limit-count`。
- **K059** 跨实例共享计数：两者对应存储策略；验证 Redis 故障与计数一致性。
- **K060** 滑动窗口与高级分布式限流：Kong Rate Limiting Advanced 企业版； APISIX 按具体算法与插件确认。
- **K061** 平滑突发与漏桶：APISIX `limit-req`；Kong 对应算法范围待核实。
- **K062** 并发限制：APISIX `limit-conn`；Kong 对应方案待核实。
- **K063** 服务整体保护额度：Kong Service Protection 企业版；APISIX 服务级插件策略。
- **K064** 根据响应计量值扣减额度：Kong Response Rate Limiting；APISIX 需核实扩展方案。
- **K065** GraphQL 查询成本限额：Kong 高级企业版插件；APISIX `graphql-limit-count`。
- **K066** AI Token 限额：Kong AI 授权插件；APISIX `ai-rate-limiting`。
### 6. 转换、适配与接口编排

- **K067** 请求头、查询参数增删改；Host、URI、方法重写：两者对应转换机制。
- **K068** 响应头、状态码、响应体修改：Kong Response Transformer 系列；APISIX `response-rewrite`。
- **K069** JSON/XML 等结构转换：Kong 高级转换/jq 等部分企业版；APISIX `body-transformer`。
- **K070** 复杂 JSON 处理：Kong jq 企业版；APISIX 模板、脚本或自定义插件。
- **K071** 自定义网关错误、维护页、固定响应：Kong Exit Transformer 企业版/Request Termination； APISIX `exit-transformer`、错误页与响应改写方案。
- **K072** URL 重定向与 HTTP 跳转 HTTPS：两者对应插件。
- **K073** REST/GraphQL 适配：分别核实两个方向，不能因插件都叫 DeGraphQL 就认定等价。 Kong 企业版 DeGraphQL 将 GraphQL 上游暴露为 REST；APISIX 目录描述为 GraphQL 到 REST 上游。
- **K074** 批量 HTTP 请求及响应汇总：Kong Datakit 等企业版方案；APISIX `batch-requests`。
- **K075** 外部 API Callout、结果参与后续处理：Kong Request Callout/Datakit 企业版； APISIX Serverless/自定义插件等方案。
- **K076** 条件工作流：Kong 插件/Datakit；APISIX `workflow`。
- **K077** API Mock：Kong Mocking 企业版；APISIX `mocking`。
- **K078** 故障、延迟注入：APISIX `fault-injection`；Kong 对应测试或扩展方案待核实。
### 7. 缓存与传输优化

- **K079** HTTP 响应缓存：Kong Proxy Cache；APISIX `proxy-cache`。
- **K080** Redis 等高级缓存：Kong Proxy Cache Advanced 企业版；APISIX 按具体后端确认。
- **K081** GraphQL 查询缓存：Kong 高级企业版插件；APISIX `graphql-proxy-cache`，mutation 绕过缓存。
- **K082** LLM 结果/语义缓存：Kong AI Semantic Cache（AI 授权）；APISIX `ai-cache`。
- **K083** Gzip/Brotli 压缩：APISIX 对应插件；Kong 底层配置支持范围待核实。
- **K084** 请求/响应缓冲、背压与流式传输：两者代理配置与插件，逐项核实内存和取消行为。
- **K085** 上游连接复用与 Keep-Alive：两者支持；核实连接池与协议边界。
### 8. 可观测性与排障

- **K086** 请求量、延迟、错误率：Kong Prometheus/Datadog/StatsD；APISIX Prometheus/Datadog 等。
- **K087** 分布式追踪：两者 OpenTelemetry/Zipkin；APISIX 另有 SkyWalking。
- **K088** 请求 ID 与上下游日志关联：Kong Correlation ID；APISIX `request-id`。
- **K089** 文件、HTTP、TCP、UDP、Syslog 日志：两者对应插件。
- **K090** Kafka 日志：Kong 企业版；APISIX `kafka-logger`。
- **K091** RocketMQ、ClickHouse、Elasticsearch、Loki、Splunk、Loggly 等日志接入： APISIX 专用插件；Kong 按官方/第三方插件分别核实。
- **K092** 云日志：APISIX 阿里云 SLS、腾讯云 CLS、Google Cloud Logging 等；Kong 集成范围待核实。
- **K093** 错误日志集中收集与轮转：APISIX `error-log-logger`、`log-rotate`；Kong 对应部署方案。
- **K094** 节点状态、运行时诊断与健康接口：区分数据面接口与平台管理能力。
- **K095** 企业 APM：Kong AppDynamics 企业版等；逐项记录外部系统依赖。
### 9. 消息与 Serverless

- **K096** HTTP 触发 AWS Lambda、Azure Functions、OpenWhisk：两者对应插件。
- **K097** OpenFunction：APISIX `openfunction`；Kong 对应扩展待核实。
- **K098** 前置/后置自定义函数：Kong Pre/Post Function；APISIX Serverless Pre/Post Function。
- **K099** 请求写入 Kafka：Kong Kafka Upstream 企业版；APISIX Kafka PubSub 等能力。
- **K100** HTTP 消费 Kafka：Kong Kafka Consume 企业版；APISIX 按 PubSub 接口范围核实。
- **K101** Confluent/Solace 生产、消费与日志：Kong 企业版/合作伙伴插件；APISIX 集成待核实。
- **K102** Kafka 协议代理与 SASL 等参数：APISIX `kafka-proxy`； 与 HTTP 写消息、消费消息及日志投递分别验收。
### 10. AI、LLM、MCP 与 Agent

- **K103** 统一模型供应商入口：Kong AI Proxy；APISIX `ai-proxy`。
- **K104** 多模型负载均衡、重试、回退、健康检查：Kong AI Proxy Advanced（AI 授权）； APISIX `ai-proxy-multi`。
- **K105** Token 计量与限流：Kong AI 授权插件；APISIX `ai-rate-limiting`。
- **K106** 系统提示词注入、参数化模板、规则允许/拒绝：两者 Prompt Decorator/Template/Guard。
- **K107** 语义话题限制、输出防护：Kong Semantic Prompt/Response Guard（AI 授权）； APISIX 对应防护范围待核实。
- **K108** 云内容安全与提示注入检测：Kong AWS/Azure/GCP/Lakera 等 AI 授权集成； APISIX AWS/阿里云/Lakera 等插件，实际检测依赖外部服务。
- **K109** AI 个人敏感信息脱敏：Kong AI PII Sanitizer（AI 授权）；APISIX 对应方案待核实。
- **K110** 提示词压缩：Kong AI Prompt Compressor（AI 授权）；APISIX 对应插件待核实。
- **K111** 检索增强与上下文注入：Kong AI RAG Injector（AI 授权）；APISIX `ai-rag`。
- **K112** LLM 缓存：Kong AI Semantic Cache（AI 授权）；APISIX `ai-cache`，核实语义范围。
- **K113** LLM 改写请求：Kong AI Request Transformer；APISIX `ai-request-rewrite`。
- **K114** LLM 改写响应：Kong AI Response Transformer；APISIX 对应方案待核实。
- **K115** 模型评估模型输出：Kong AI LLM as Judge（AI 授权）；APISIX 外部评测集成待核实。
- **K116** API 转 MCP Tools：Kong AI MCP Proxy（AI 授权）；APISIX `openapi-to-mcp`。
- **K117** MCP 代理、工具聚合与可观测性：Kong AI MCP Proxy（AI 授权）； APISIX 按具体插件能力核实。
- **K118** MCP OAuth2：Kong AI MCP OAuth2（AI 授权）；APISIX 认证组合需验证。
- **K119** SSE 到 stdio MCP 桥接：APISIX `mcp-bridge` 已弃用，不作为新部署推荐方案。
- **K120** A2A Agent 流量治理：Kong AI A2A Proxy（AI 授权）；APISIX 专用能力待核实。
### 11. API 平台、商业化与组织治理

- **K121** 调用者、凭证与分组管理：两者对应网关资源。
- **K122** API 文档发布、开发者门户：Kong Dev Portal 配套产品；APISIX 需外部平台。
- **K123** 开发者应用注册、API 申请与审批：Kong Dev Portal 对应能力；APISIX 需平台编排。
- **K124** 按客户订阅权益放行：Kong Entitlement Enforcement 商业能力； APISIX 认证、配额与外部订阅服务组合。
- **K125** API 调用量和 AI Token 用量计费：Kong Konnect Metering & Billing 授权附加能力； APISIX `lago` 向外部 Lago 上报事件，不等于内置账单和支付系统。
- **K126** 管理员 RBAC、审计与多团队权限：Kong 企业管理/Konnect；APISIX 需核实控制面及外部治理。
- **K127** 配置隔离与多租户：Kong Workspaces 等；APISIX 需规划资源、控制面及运行环境隔离。
- **K128** 多集群、多环境与 API 目录：Kong Konnect 配套；APISIX 自建或生态平台。
### 12. 部署、自动化与扩展

- **K129** 管理 API 动态更新路由、上游与插件：两者支持。
- **K130** 声明式配置与版本管理：Kong DB-less/decK；APISIX Standalone 等模式。
- **K131** 控制面/数据面分离：核对 Kong Hybrid 与 APISIX 对应部署模式。
- **K132** 容器与 Kubernetes 部署：两者支持。
- **K133** Kubernetes Ingress、Gateway API：各自 Controller，逐项确认资源和一致性支持范围。
- **K134** GitOps/CI/CD：Kong decK/Terraform/Kubernetes；APISIX 配置文件/Admin API/Kubernetes。
- **K135** 多云、混合云与托管数据面：区分自行部署与 Kong Konnect 托管能力。
- **K136** 密钥外置、配置加密与证书轮换：Kong Vault 等；APISIX Secret 等，核对版本边界。
- **K137** 自定义 Lua 插件：两者支持。
- **K138** 外部语言插件：Kong 按开发机制核实；APISIX Java/Go/Python Plugin Runner 等。
- **K139** Wasm 扩展：APISIX 有官方开发入口；Kong 按版本核实。
- **K140** 插件阶段、执行顺序与前后置扩展：两者分别核实，不假设跨阶段语义等价。

## 已核对的部分证据

本批核对基线：`4f216970`。下列状态只反映所列代码与测试的静态核对；本批没有执行测试或竞品差分。

- **K001 HTTP/HTTPS 反向代理 — 部分实现。** [语言卡](language-card.md)提供 `upstream` 和显式负载均衡的 `forward`；[集成测试](../tests/test_integration.cc) 包含 HTTP 转发、TLS 和请求分帧路径。仍需分别对照普通转发与各策略组合的 HTTP 版本、流式 body、错误和连接复用；不能将单一请求测试视为 REST 全覆盖。
- **K002 HTTP/2 / 原生 gRPC — 部分实现。** [语言卡的 Native gRPC forwarding](language-card.md#native-grpc-forwarding)描述下游 h2c/TLS、上游 `.http2` 和四类 RPC 流；[gRPC 测试](../tests/test_grpc_proxy.cc)包含 epoll/io_uring 的流和连接池用例。该路径对消息和元数据按文档保持不透明，受头、缓冲和连接资源上限约束；协议及竞品行为矩阵仍待运行验收。
- **K003 gRPC-Web — 当前 `.http2` 转发选项不实现。** [语言卡](language-card.md#native-grpc-forwarding)明确将 gRPC-Web 排除在该选项之外。浏览器跨域、文本/二进制 framing、trailers 与流式能力仍需设计、实现及验证；此结论不推断任意外部适配器的能力。
- **K004 HTTP/JSON 到 gRPC 转码 — 当前 `.http2` 转发选项不实现。** 同一[语言卡](language-card.md#native-grpc-forwarding)明确排除 JSON transcoding；尚需定义 schema、方法映射及双向错误语义并验证。
- **K007 SSE / 流 — 部分底座，场景未验收。** [集成测试](../tests/test_integration.cc)包含大请求体分段转发、早期上游响应及取消相关路径；这不是 SSE 语义或竞品等价的证明。需单独验证持续响应、缓冲、超时、背压和客户端断开。
- **K009 TLS 终止 / SNI / 透传 — 部分证据。** [TLS 实现](../src/runtime/tls.cc)包含客户端验证及 SNI 设置，[集成测试](../tests/test_integration.cc)包含 TLS 握手和 HTTP/2 ALPN。上游客户端 SNI 不能证明下游 SNI 路由或 TLS 透传；后两项及证书轮换仍需单独审计和验收。

- **K005 WebSocket 代理 — 部分实现，未完成竞品验收。** Rut 提供 `return websocket(chat)` 透明代理入口（[语言卡](language-card.md)）；[集成测试](../tests/test_integration.cc)包含 WebSocket 连接与分片往返。还需固定 Nginx/Envoy 版本并比较握手、超时、背压、半关闭和扩展等行为，不能据此声明完整兼容。
- **K006 消息检查 — 部分实现，未完成竞品验收。** 终止模式支持 `forward`、`drop`、`close` 和分片重组；[实现](../include/rut/runtime/callbacks_impl.h) 将消息上限约束在一个 slice 内，[测试](../tests/test_ws_terminate.cc)覆盖跨帧 UTF-8、控制帧和总大小限制。[#937](https://github.com/hurricane1026/Rut/pull/937) 已合并；大消息、压缩内容检查和完整竞品差分仍待处理。

每项完成前应补：版本化竞品证据、`.rut` 可运行示例、当前实现和测试链接、正常及失败/取消/回收路径、所需后端和协议矩阵。外部服务或授权约束要单独记录。
