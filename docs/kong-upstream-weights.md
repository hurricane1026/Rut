# Kong 核心能力：静态上游权重

对应场景 K017 的静态数据面子集。Kong 的
[负载均衡说明](https://developer.konghq.com/gateway/load-balancing/)
将 round-robin 定义为加权分流；
[Target 配置](https://developer.konghq.com/gateway/entities/target/)
提供每目标权重。Rut 使用原生 upstream 配置表达相对权重，不导入 Kong Admin API。

```swift
upstream api {
    backends: ["127.0.0.1:9001", "127.0.0.1:9002", "127.0.0.1:9003"]
    weights: [3, 1, 0]
}
route GET "/" { return forward(api, load_balance: .roundRobin) }
```

- 最多 8 个后端，一一对应 0–1000 的整数字面量权重；省略时均为 1。
- 权重 0 表示禁用，不能因所有其他后端已摘除或重试而重新启用，也不会向其发起主动健康探测。
- 全零配置允许发布；没有可选目标时拒绝转发，HTTP 返回 503。
- `.roundRobin` 平滑加权；`.leastRequests` 按 active/weight 比较，平局时加权选择。
  相同权重保留既有轮转顺序。请求和 RPC 的在途计数、释放与取消继续复用原有路径。
- 健康摘除、恢复和重试排除改变可选集合时重置分流积分，避免累积欠账导致恢复突发。
- 积分归属配置、shard 和 forward 调用点；配置 RCU 替换会建立新状态，旧请求继续释放
  原快照上的计数。热路径不分配内存。每快照在 64 shard 上界增加 544 KiB 固定状态。
- Native artifact 布局版本升为 19，旧产物需要重新编译。

验证入口：

```bash
./build/tests/test_frontend --filter=frontend.upstream_weights
./build/tests/test_network --filter=weighted_load_balance
./build/src/test_native_program --filter=native_program.weighted_upstream
ctest --test-dir build -R '^test_weighted_upstream_' --output-on-failure
```

真实套接字用例在 epoll/io_uring 上分别验证 H1/H2 下游、3:1 分流、最少请求的空闲平局、
禁用目标不接收流量、全零 503，以及连接拒绝后切换到未尝试的启用目标。
这些测试不启动 Kong，不宣称逐请求调度顺序或整个 Kong Upstream/Target 控制面的完全兼容。
动态 Target API、DNS/SRV 权重展开、一致性哈希、会话粘性及主动健康检查的全部能力仍需独立验收。

本地验证记录：Release / Clang 22 / LLVM 22，Linux；全前端 1312 项（22979 checks）、
全网络 1671 项（568587 checks）、Native 88 项全部通过；真实转发与路由／ELF 回归
11/11 通过；全 gRPC 104 项（132394 checks）通过，包含按权重选择、全禁用拒绝及已有 RPC 释放计数。
此记录不是实时 Kong 差分或 sanitizer 结果。多快照测试使用 mmap Arena，
避免在默认线程栈上同时放置多个大型 RouteConfig。
