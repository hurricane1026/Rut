# Kong 路由与策略差分基线

审计基线：Rut `25a9ca4ba` 的路由实现；Kong OSS **3.9.1**，DB-less、传统 JSON 路由、
`strip_path: false`、`preserve_host: true`。Kong 镜像固定为
[`tests/pinned-kong-image.txt`](../tests/pinned-kong-image.txt) 中的不可变 manifest digest；
不使用 `latest`，不把此版本的结果外推到其他版本或 Enterprise 插件。

本地已在 epoll、io_uring 各运行 21 项成对请求：**16 项观察一致，5 项存在明确差异**。
通过差分测试意味着两端行为符合各自冻结的预期，**不表示 21 项全部兼容**。

## 验收方式

[`test_kong_differential.py`](../tests/test_kong_differential.py) 启动两个可区分的真实 HTTP
上游、固定镜像的 Kong 和从 `.rut` 启动的 Rut。每项比较状态、响应体、实际到达的上游、
上游收到的路径及策略头；不会用最终状态相同代替路由正确。
两端配置分别编写，当前没有 Kong 配置导入器。Rut 策略是普通 `.rut` 条件与头操作，
不增加插件运行语言、生产依赖或网关关键字。

冻结预期及分类位于
[`kong-routing-cases.json`](../tests/fixtures/kong-routing-cases.json)。
`equivalent` 项必须两端一致；`known-difference` 项必须分别符合其精确预期，且差异仍存在。
任何一端变化都需要重新审阅，测试不会自动更新预期。`--observe` 只打印观察，不修改 fixture。

## 已验证的一致子集

- GET 查询串（含重复 query）、POST 请求体、HEAD、DELETE 的普通转发。
- 根路由回退、带斜杠前缀与相似路径、路径大小写。
- Host/header/method 条件及其不匹配时的回退；这些只是本例的明确条件组合。
- 更具体路由的 403 本地拒绝。
- 同名 `request-transformer` 在本例中的 global、Service、Route 覆盖结果；
  包括删除客户端伪造的 `X-Policy` 后设置受信任值。

这不等于通用 Kong 路由器、完整表达式优先级或插件作用域解析器已经实现。
Consumer、Consumer Group、复合 scope、动态插件排序和插件 phase 均尚未进入本基线。

## 已复现的 P0 差异

| 用例 | Kong 观察 | Rut 观察 | 影响 |
| --- | --- | --- | --- |
| 配置 `/api/`，请求 `/api` | 回退到 fallback | 选择 api | 路由尾斜杠语义不同 |
| 配置 `/catalog`，请求 `/catalogue` | 选择 api | 回退到 fallback | Kong 字节前缀与 Rut 分段前缀不同 |
| `/api//users` | 上游收到 `/api/users` | 上游收到原始双斜杠 | 转发路径不同 |
| `/api/%75sers` | 上游收到 `/api/users` | 上游收到原始转义 | unreserved 解码不同 |
| `/api/../else` | fallback 收到 `/else` | api 收到 `/api/../else` | 规范化同时改变路由及上游目标 |

最后一项必须先于扩大插件覆盖面处理：同一请求在两端会进入不同的策略与上游。
当前普通 Rut 路由契约不能被悄悄改成 Kong 契约；后续需要明确区分原始 target、用于匹配的
规范化路径、转发路径和字节/分段前缀。扩展验收还应包含 encoded dot、encoded slash、
重复转义、无效转义、query 保留和多路由优先级，之后才能确定可接受的 Kong 配置子集。

## 尚未覆盖的兼容工作

1. 规范化/匹配/转发三者的一致模型，以及 `strip_path`、`path_handling`、`preserve_host` 的组合。
2. 通用 Service/Route/Upstream/Target/Consumer 配置映射；未知或无法表达的配置显式拒绝。
3. 认证先于 Consumer 策略、同名插件配置覆盖、Consumer Group 冲突及 phase 顺序。
4. 配置原子发布、更新/回滚及 Admin API/decK 兼容；RCU 热更新基础不代表这些已兼容。
5. 上游治理与跨节点限流，仍按主计划单独推进。

本轮 HTTPS 上游实现属于独立运行时工作包；本基线只发送普通 HTTP，不借此宣称已验证 Kong
HTTPS/mTLS、重试、超时、缓存、gRPC、WebSocket 或其他协议的等价性。

## 复现与 CI

```bash
docker pull "$(cat tests/pinned-kong-image.txt)"
RUT_KONG_DIFFERENTIAL_REQUIRED=1 \
  python3 tests/test_kong_differential.py --server build/src/rut --backend epoll \
    --report build/kong-differential-epoll.json
RUT_KONG_DIFFERENTIAL_REQUIRED=1 \
  ctest --test-dir build --output-on-failure --no-tests=error -L kong
```

需要 Linux、Docker、已构建的启用 JIT 的 Rut。测试只启动并删除自己唯一命名的临时容器；
监听和上游均限定为 loopback，Kong Admin API 关闭。配置通过环境字符串传入，避免主机挂载
权限/SELinux 影响语义验收。普通非 Docker CI 可使用 `-LE docker`。

缺少 Docker 或固定镜像时，本地 CTest 返回 skip；设置
`RUT_KONG_DIFFERENTIAL_REQUIRED=1` 后缺少 oracle 是失败。
独立工作流 [Kong compatibility baseline](../.github/workflows/kong-compatibility.yml)
构建当前 checkout、拉取固定 digest，并在两个后端运行，上传实际 JSON 观察。
测试不依赖系统 OpenSSL CLI，也不承担配置转换器职责。

官方语义参考：[路由](https://developer.konghq.com/gateway/entities/route/)、
[插件作用域](https://developer.konghq.com/gateway/entities/plugin/)、
[DB-less 配置](https://developer.konghq.com/gateway/db-less-mode/)。
