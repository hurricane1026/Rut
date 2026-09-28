# 多场景路由样本与四端对比矩阵

## 当前交付状态

- `generate.py`：20 类合成路由样本、两种明确的匹配契约、预期 route ID / 参数捕获、可重复请求序列。
- `comparison.py`：Rut、Nginx、Envoy、Linkerd 四端的必测清单和结果索引校验。
- `tests/test_routing_corpus.py`：参考匹配器的独立预期、样本与序列、自检及漏测拒绝测试，注册到 CTest。
- `dispatch_matrix.cc` / `run_matrix.py` / `summarize_matrix.py`：路由结构比较、正确性预检与耗时摘要。
- **当前没有这套新样本的四代理整机实测结果，也没有新增四代理的完整启动或性能采样器。**
  Nginx/Envoy 已有真实进程差分框架可继续接入；Linkerd 的控制面/代理部署适配器需要补齐。

样本均为 synthetic；大型互联网场景是多业务网关的合成模型，不代表任何公司的生产配置。
框架文档提供路径形态参考。此处使用统一的 corpus 契约，不声称重现各框架的优先级、
自动 HEAD/OPTIONS、类型校验、尾斜杠重定向或异常处理。

本机优化前实测见 [2026-09-29 结果](results-20260929.md)，
后续实现与复测见 [第一轮优化](optimization-20260929.md) 和
[第二轮结构化选择](optimization-round2-20260929.md)、
[第三轮紧凑元数据](optimization-round3-20260929.md)、
[第四轮按回溯需求选择](optimization-round4-20260929.md)。

## 场景

| 类别 | profile | 代表路径形态与目的 |
| --- | --- | --- |
| 极简 | `root_only` | 单根路由；检验直接分派的价值 |
| 极简静态地址 | `tiny_static` | `/health`、`/ready`、`/live`、`/metrics`、`/index.html`、`/robots.txt`、`/favicon.ico`、`/version`；1/2/4/8 条 |
| 短路径 | `flat_static` | `/projects`、`/users`；少量比较与数组候选 |
| 相似前缀 | `prefix_collision` | `/projects`、`/projectsx`、`/projects/v1`；边界和最长前缀 |
| 公共长前缀 | `shared_prefix` | `/internal/platform/production/control/services/projects/status` |
| CDN | `cdn_assets` | 哈希 JS 文件、图片、多层静态目录、文件后缀 |
| SaaS 网关 | `saas_gateway` | `/api/v1/projects`、`/admin/projects`、`/webhooks/projects` |
| SaaS 租户 | `saas_tenant` | `/api/v1/tenants/:tenant/projects/:id`，同路径多方法 |
| 大型互联网网关 | `internet_gateway` | 多服务、多版本、搜索/事件/Feed/交易入口 |
| 大型互联网资源 | `internet_resources` | 多级评论、reaction、bucket/object |
| PHP Laravel | `php_laravel` | REST 资源、管理路由、嵌套 ID |
| PHP Symfony | `php_symfony` | locale、slug、管理分组 |
| PHP WordPress/CMS | `php_wordpress` | `/wp-json/wp/v2/projects/:id`、插件脚本入口 |
| Java Spring MVC | `java_spring` | 版本 API、资源、业务动作 |
| 传统 Java | `java_legacy` | context path、`.do` / `.action` 后缀；合成历史应用形态 |
| Ruby Rails | `ruby_rails` | index/create/new/show/edit/update/destroy 的方法和路径、嵌套资源 |
| Go ServeMux | `go_serve_mux` | method + path、`latest` 与参数的交叉 |
| Python Django | `python_django` | 年月归档、slug、尾斜杠、多级管理路径 |
| Python FastAPI | `python_fastapi` | 固定 `me` 与动态 ID 路由 |
| Python Flask | `python_flask` | 简短 endpoint、登录多方法、用户名和 slug |

`:name` 是 corpus 中统一的单段参数表示。框架原生写法转换为该表示，
不把 Symfony/Flask/Django 的 converter 或约束误作 Rut 已支持的语法。
扩大规模时循环资源模板，资源名使用 `projects` 等名称并在后续轮次加固定序号。
它衡量的是扩大的同类形态；不会宣称合成的 4096 条路由来自真实应用。

## 生成与检查

```sh
python3 bench/routing/generate.py --list
python3 bench/routing/generate.py --output build/routing-corpus
python3 bench/routing/comparison.py build/routing-corpus/manifest.json \
  --output build/routing-corpus/comparison-plan.json
python3 tests/test_routing_corpus.py
```

默认每个可扩展 profile 使用 **1 / 2 / 4 / 8 / 16 / 32 / 64 / 128** 条路由。
`root_only` 固定一条；`tiny_static` 固定 8 个静态地址，只取 1/2/4/8 条，大于 8 的规模会记录在 `excluded_sizes`。另含独立的 root、前缀边界、方法优先级、静态/参数重叠回归样本。
JSON 中包含原始 request target、规范化路径、预期 route ID、参数捕获和请求索引序列。
`manifest.json` 保存输入 SHA-256；旧输出目录可能留有其他生成批次的文件，runner 必须只读取 manifest 列出的文件。

容量压力单独生成：

```sh
python3 bench/routing/generate.py \
  --profiles internet_gateway internet_resources \
  --sizes 512 1024 4096 --output build/routing-stress
```

超过 Rut 当前 128 路由容量的样本显式标为 `exceeds_128`；不能作为 Rut 已成功载入的样本。
128 条以内探测每条路由；更大规模取固定种子的最多 64 条代表路由，包含首/中/末位置，
`sampled_route_ids` 记录实际覆盖。`uniform_sampled_endpoints` 只在这些端点上均匀取样。

## 语义与流量维度

`exact` 和 `segment_prefix` **分别比较**，不得拿精确 hash 的耗时直接对比前缀 ART。
两组均剥离 query/fragment 和最外层斜杠；不做百分号解码或内部斜杠合并。
这是一份对候选实现的输入契约，代理配置适配器须先证明自身能表达它。

匹配顺序：逐段 literal 优先于参数；同一前缀下更深终端优先；同一终端指定方法优先于 ANY；
仍相同取最早声明。HEAD 不隐式使用 GET；OPTIONS 不隐式生成结果。

每条代表路由包含 endpoint、query、descendant、同段 suffix、HEAD、OPTIONS；另有 root 和未注册路径。
尾段是参数时添加 `xyz` 可能仍然命中；根 ANY 前缀可能完全没有 miss。样本通过参考匹配器计算结果，
不会把所有变异请求强行归类为 miss。重复斜杠、编码斜杠、点段、编码 Unicode 和超长路径是 `observe`，
暂不进入有通过标准的性能序列。

流量序列：首/中/末位置、代表端点均匀分布、约 80% 首端点热点、命中/未命中混合、有实际 miss 时的纯 miss。
固定 seed，所有候选使用完全相同的序列。重新排序路由表、冷热缓存、不同连接数应作为 runner 的独立维度，
不能偷偷改变样本输入。

## 极简静态 URL 专组

只生成极简静态地址：

```sh
python3 bench/routing/generate.py --profiles root_only tiny_static \
  --sizes 1 2 4 8 --output build/routing-static
```

`root_only` 与 `tiny_static` 同时产生两种执行模式，索引不允许互相替代：

- `local_static`：固定 URL 直接生成静态响应，body 大小 0 / 16 / 1024 / 65536 字节。
  路由选择的基线以 0/16 字节为主，其余用于区分发送成本。必须证明上游未被联系。
- `proxy`：相同的固定 URL 转发到相同的受控上游。四端使用同一 body、方法和连接模式。

Linkerd 的公开 HTTPRoute filter API 未提供与 Nginx `return` / Envoy `direct_response` 同等的任意静态 body 响应。
因此 `local_static` 的 Linkerd 行要求明确 `unsupported` 和原因，不计作通过，不用额外后端伪装本地返回。
`proxy` 模式仍要求四端实测。四端无法都执行的模式不发布四端性能排名。
静态文件/sendfile 涉及磁盘与页缓存，后续应单独建实验，不合入这组固定地址/固定 body 路由基线。

## 必须覆盖的四端

| 对象 | 配置与执行方式 | 必须留下的证据 |
| --- | --- | --- |
| Rut | 普通 `.rut`；编译器自动选择分派实现 | 源码/二进制摘要、所选实现、配置构建/JIT 时间、配置内存、命中上游 |
| Nginx | 独立生成等价原生配置 | 仓库固定镜像摘要、配置、实际匹配结果及 upstream 日志 |
| Envoy | 独立生成等价原生配置 | 仓库固定镜像摘要、bootstrap/route 配置、实际匹配结果及 upstream 日志 |
| Linkerd / linkerd2-proxy | 注入客户端的 outbound proxy + 生效的 HTTPRoute + 后端 Service | proxy 与控制面摘要、Accepted/ResolvedRefs 等生效证据、实际拓扑与上游日志 |

Linkerd 的动态请求路由基于 Gateway API HTTPRoute；后端选择在 outbound 侧执行。
必须让请求经过真实 outbound 代理，单纯连接服务端 sidecar 或 Kubernetes port-forward 不能证明该路由已执行。
参考 [Linkerd HTTPRoute](https://linkerd.io/docs/reference/httproute/) 和
[动态请求路由](https://linkerd.io/docs/features/request-routing/)。

四端全量矩阵使用同一 corpus hash。Nginx/Envoy 的镜像沿用
[`pinned-nginx-image.txt`](../../tests/pinned-nginx-image.txt)、
[`pinned-envoy-image.txt`](../../tests/pinned-envoy-image.txt)。Linkerd 的版本/摘要与测试部署尚未固定，
必须在运行前补齐。固定资源、禁用或统一非测试功能、记录 TLS/mTLS/代理跳数；
一跳明文 ingress 与双 sidecar mTLS 的 QPS 不能汇总为同一排行榜。

### 两层对比

1. **结构微基准**：直接分派、数组/比较分支、满足精确契约时的 hash、ART、ART JIT、SegmentTrie。
   先逐探针验证 ID/捕获；各实现统一接收已规范化路径，规范化成本另测。
   有参数或不支持的语义必须报告不适用。现有 `bench_dispatch_compare.cc` 的精确/前缀混测不能用来定阈值。
2. **真实代理差分与性能**：四端实际监听、联系可区分上游。先核对方法、路径/query、route ID、
   转发次数、状态、请求/响应 body 及连接生命周期，再测 QPS、p50/p95/p99、CPU、RSS、启动/重载。
   头顺序/大小写等严格 HTTP 兼容性仍分别走 Nginx/Rut 和 Envoy/Rut 差分，不能要求不同产品默认报文完全相同。

### 验收索引

`comparison.py` 生成的每行初始为 `not_run`。缺少任一端、可执行行被跳过、hash 不一致、探针不完整均退出非零。
预先列明的非通过行包括 Linkerd `local_static`、Rut `exact` 合约和超过 128 条路由的 Rut case；这些行都必须显式记录 `unsupported` 和非空原因。Rut exact 与超容量同时成立时，超容量 prerequisite 优先：

```sh
python3 bench/routing/comparison.py build/routing-corpus/manifest.json \
  --results /path/to/runner-result-index.json
```

结果索引是一组 JSON 对象。可执行行要求 `case`、`engine`、`execution_mode`、`response_bytes`、`case_sha256`、`state: "passed"`、
完整的 `asserted_probes` 数量、`failed_probes: 0`，以及二进制/配置/探针/上游/环境证据摘要。
Linkerd 额外要求控制面、路由状态证据和 topology。该工具检查索引的完整性；
实际 runner 还须保存并验证证据文件，不能把手填索引当作实测通过。

## 框架来源

仅据以下官方资料设计路径形态，访问日期 2026-09-28：

- [Laravel routing](https://laravel.com/docs/12.x/routing)
- [Symfony routing](https://symfony.com/doc/current/routing.html)
- [WordPress REST reference](https://developer.wordpress.org/rest-api/reference/)
- [Spring MVC request mapping](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-requestmapping.html)
- [Rails routing](https://guides.rubyonrails.org/routing.html)
- [Go 1.22 routing](https://go.dev/blog/routing-enhancements)
- [Django URL dispatcher](https://docs.djangoproject.com/en/5.2/topics/http/urls/)
- [FastAPI path parameters](https://fastapi.tiangolo.com/tutorial/path-params/)
- [Flask routing](https://flask.palletsprojects.com/en/stable/quickstart/#routing)

## 路由结构微基准（segment_prefix）

```sh
cmake --build build --target bench_routing_matrix
mkdir -p build/routing-measurements
python3 bench/routing/run_matrix.py > build/routing-measurements/input.txt
build/bench/bench_routing_matrix --validate < build/routing-measurements/input.txt
flock /tmp/rut-clean-bench/bench.lock taskset -c 6 build/bench/bench_routing_matrix \
  < build/routing-measurements/input.txt \
  > build/routing-measurements/raw.csv 2> build/routing-measurements/validation.log
python3 bench/routing/summarize_matrix.py build/routing-measurements
```

计时前必须自行确认没有其他构建/压测；CPU 6 是本机示例，需按机器调整。
输入只接受 `run_matrix.py` 生成的受信数据。当前 149 组配置覆盖 20 类路径、
1–128 条路由，每条轨迹 1024 项，8 次重复。线性/ART 每次 131072 次查找、8192 次预热；
SegmentTrie 每次 8192 次查找、1024 次预热。优化前的历史报告使用过
128 次查找、16 次预热，以控制当时每次百微秒的成本；具体以各次报告为准。
每次将序列起点前移 128，8 次合计覆盖完整 1024 项序列；
当前每次重复覆盖完整序列多次；比较应结合 min/max，不解释微小差距。
轮换候选计时顺序；相同规范化路径、HTTP 方法和分段前缀语义；使用不内联调用
与输出校验和避免消除查找。全部 asserted probes 的 route ID 校验通过后才计时。

候选为按优先级排列的线性扫描、SegmentTrie、标量 ART、JIT ART；包含参数的
配置只测前两者。`needs_segment_aware()` 的真实选择记录在 stderr，摘要报告
该选择相对这些候选中最小中位数的比值及各候选 min/max。JIT 不可用时该基准
不适用，不能把标量结果冒充 JIT。线性扫描只作为比较基线，未接入生产选择器。

边界：只验证 route ID，未计入参数捕获输出、规范化、配置/JIT 构建或网络成本；
不是 `.rut` 完整请求路径测试。未测 exact/hash、专用单路由生成代码、不同 ISA
与硬件、真实生产流量；参数候选的比较不能推导包含捕获操作的生产收益。
四代理整机测试仍需独立执行，不得以此微基准替代。
