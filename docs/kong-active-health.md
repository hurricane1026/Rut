# Kong 核心能力：主动 HTTP 健康检查

对应 K019 的主动 HTTP 探测数据面子集。Kong 的[健康检查说明](https://developer.konghq.com/gateway/traffic-control/health-checks-circuit-breakers/)
将周期探测用于故障摘除和恢复。Rut 沿用已有配置，不引入插件运行语言、关键字或依赖：

```swift
upstream api {
    backends: ["127.0.0.1:9001": 3, "127.0.0.1:9002": 1]
    minimum_healthy_weight_percent: 50
    health_check: { path: "/healthz", interval: 1s, status: 200 }
}
route GET "/" { return forward(api, load_balance: .roundRobin) }
```

- Linux epoll 和 io_uring 都会按周期发送真实 HTTP/1.1 GET，比较完整响应头中的状态码。
  连续失败达到阈值时摘除目标，连续成功达到阈值时恢复；相反结果重置连续计数。
  普通请求连接成功不能清除主动摘除。
- 仅支持当前明文 HTTP/1 上游；HTTPS、HTTP/2/gRPC 健康协议不在本次范围。
  使用单个预期状态和统一探测周期。`failure_threshold` 与 `success_threshold`
  分别指定摘除和恢复所需的连续探测次数，取值 1–255，省略时各为 1。
- 每个 shard、每个目标最多一个在途探针。权重 0 的目标不接收探测或业务流量。
  每次 sweep 最多发出 32 个探针，并为业务连接保留 64 个空闲槽；预算不足时延后。
- io_uring 在 sweep 发起探针时另预留 16 个 SQ 提交位置；探针使用连接自己的地址和请求/响应切片。
  超时或关闭先取消准确的 I/O episode，SQ 满时保留取消重试账本；所有 target/cancel
  完成之前不释放切片、连接槽或在途标记。关闭探针不改变业务请求/连接指标。
- 探针生命周期由上游超时约束，逐包输入不会延长截止时间。排空期间不发起新探针；
  强制排空和 shutdown 会取消已有探针。
- 热更新重新安排周期并重置健康判定。旧探针的结果必须同时匹配配置指针和身份，
  即使新配置复用了相同地址也不能污染其健康状态；内核不借用旧配置中的 sockaddr。

`minimum_healthy_weight_percent` 默认为 0，所有启用目标都被摘除时沿用 fail-open。
设置为正数时，Rut 根据主动与被动健康判定计算健康目标的权重占比。占比低于门槛时，
新转发或显式上游连接返回 503。示例中，权重为 3 的目标被摘除后，只剩 25% 健康容量。
健康判定和容量计算均在各 shard 内完成。

验证入口：

```bash
cmake --build build --target test_health_probes rut
ctest --test-dir build -R '^test_(health_probes|active_health_)' --output-on-failure
```

独立 C++ 用例通过真实 loopback sockets 验证两后端的失败/恢复、超时和取消回收、
槽位预留、零权重、原地址配置替换、SQ 满的取消重试以及旧配置销毁后的异步 connect。
真实网关用例分别在 epoll/io_uring 上通过 H1/H2 下游观察 A/B 分流、健康失败后的摘除、
门槛触发时的 503 和恢复后的重新分流，同时验证显式上游连接也遵守门槛。
权重为 0 的目标在测试中未收到探针或业务请求。

主动探针合入时的 Linux 验证记录：13 个 C++ 探针测试（278 项检查）在 Release 和 ASan/UBSan 下通过，
14 个真实网关/分流/路由/ELF CTest 项全部通过，另有 1,674 个网络、1,312 个前端、
104 个 gRPC 与 88 个 Native artifact 回归通过。未运行 macOS kqueue 或真实 Kong 对照测试。

Native artifact 版本 22 记录健康权重百分比，并保留探测阈值和探针配置身份。旧产物需重新编译。
