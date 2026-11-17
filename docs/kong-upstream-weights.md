# Kong 核心能力：静态上游权重

对应场景 K017 的静态数据面子集。Kong 的
[负载均衡说明](https://developer.konghq.com/gateway/load-balancing/)
将 round-robin 定义为加权分流；
[Target 配置](https://developer.konghq.com/gateway/entities/target/)
提供每目标权重。Rut 使用原生 upstream 配置表达相对权重，不导入 Kong Admin API。

```swift
upstream api {
    backends: ["127.0.0.1:9001": 3, "127.0.0.1:9002": 1, "127.0.0.1:9003": 0]
}
route GET "/" { return forward(api, load_balance: .roundRobin) }
```

- 最多 8 个后端，字典的 key 为地址、value 为 0–65535 的整数字面量权重。
  既有字符串数组写法表示各后端权重均为 1；不支持独立的 `weights` 字段。
  重复字典 key、混合数组与字典项、空集合和非法权重在编译时拒绝。
- 权重 0 表示禁用，不能因所有其他后端已摘除或重试而重新启用，也不会向其发起主动健康探测。
- 全零配置允许发布；没有可选目标时拒绝转发，HTTP 返回 503。
- `.roundRobin` 平滑加权；`.leastRequests` 按 active/weight 比较，平局时加权选择。
  相同权重保留既有轮转顺序。请求和 RPC 的在途计数、释放与取消继续复用原有路径。
- 健康摘除、恢复和重试排除改变可选集合时重置分流积分，避免累积欠账导致恢复突发。
- 积分归属配置、shard 和 forward 调用点；配置 RCU 替换会建立新状态，旧请求继续释放
  原快照上的计数。热路径不分配内存。每快照在 64 shard 上界增加 1056 KiB 固定调度状态，权重表另增 1 KiB。
- Native artifact 布局版本升为 19，旧产物需要重新编译。

验证入口：

```bash
./build/tests/test_frontend --filter=frontend.upstream_weights
./build/tests/test_network --filter=weighted_load_balance
./build/src/test_native_program --filter=native_program.weighted_upstream
ctest --test-dir build -R '^test_weighted_upstream_' --output-on-failure
```

真实套接字用例在 epoll/io_uring 上分别验证 H1/H2 下游、最大权重 65535 下的 3:1 分流、最少请求的空闲平局、
禁用目标不接收流量、全零 503，以及连接拒绝后切换到未尝试的启用目标。
这些测试不启动 Kong，不宣称逐请求调度顺序或整个 Kong Upstream/Target 控制面的完全兼容。
动态 Target API、DNS/SRV 权重展开、一致性哈希、会话粘性及主动健康检查的全部能力仍需独立验收。

Kong 3.9.1 的 [Target schema](https://github.com/Kong/kong/blob/3.9.1/kong/db/schema/entities/targets.lua)
明确将权重范围定义为 0–65535；Rut 使用同样的范围。使用字符串数组时权重均为 1，
与 Kong 默认每目标 100 的等比例分流一致。

本地最终验证（Linux / Release / Clang 22 / LLVM 22）：全前端 1312 项、全网络 1671 项
（5280280 checks）、Native 88 项及 gRPC 104 项通过。真实转发／路由／普通 server ELF
检查 11/11 通过，包含 65535 权重的真实 H1/H2 分流。未运行本轮 live Kong 差分或 sanitizer。
多快照及大栈帧测试通过项目现有 mmap Arena 持有配置，以保持默认线程栈预算。

字典语法更新后再次通过全前端 1312 项（22989 checks）、Native 88 项以及上述
11 项真实转发／路由／ELF 检查；parser clang-tidy 和受影响文件格式检查通过。
网络及 gRPC 全量结果来自调度实现相同的前一提交，本次未重复运行。
