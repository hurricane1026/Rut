# epoll 大响应 buffer 优化（2026-10-07）

修改 `EpollEventLoop`，复用已有 shared body pump 的升级/归还接口和 SlicePool bulk 分配器。明文 Content-Length 响应剩余至少128KiB时，把上游接收区从16KiB升级到256KiB；不等待填满才发送。部分发送仍引用旧内存时不迁移；保留缓冲字节；TLS、短响应、chunked或分配失败保持原路径。响应结束归还bulk buffer，保持普通keep-alive接收区。每shard bulk cache上限16MiB，惰性分配；不引入依赖、Connection字段、异步模型或DSL变化。

## Rut 自身 A/B 验收

1MiB HTTP native-streaming；worker/shard1，server CPU2、origin CPU3、client CPU5/7。每轮预热5s，c128测量20s、c1测量10s。顺序baseline→candidate→candidate→baseline。c128双方下游短连接均重建origin，长连接在预检确认origin复用。两轮RPS及每轮p99算术平均，p99平均不是合并分布分位数。16行全部有效，预热、测量错误均零，逐字节响应预检通过。

| 并发 | 连接 | 原RPS | 新RPS | 提升 | 原/新 p99 ms | 原/新结束RSS MiB |
|---|---|---:|---:|---:|---|---|
| 128 | close | 1538.8 | 2706.5 | +75.9% | 84.6250 / 48.4155 | 74.82 / 89.71 |
| 128 | keepalive | 1474.5 | 2993.2 | +103.0% | 89.3230 / 44.2620 | 75.37 / 100.53 |
| 1 | close | 1435.7 | 2530.6 | +76.3% | 0.7340 / 0.4195 | 69.33 / 69.74 |
| 1 | keepalive | 1643.6 | 3002.7 | +82.7% | 0.6875 / 0.3835 | 69.29 / 69.71 |

结束RSS可能包含尚未清理的活跃连接，不是峰值或完全空闲时RSS；扩大body接收区存在内存代价。c128最终验收关闭adaptive cache实验；此前32MiB实验批次只保留诊断数据。c1峰值借用一个bulk，不会触发adaptive cache。全部负载编译进程监控0命中，但不保证宿主没有任何其他活动。

## 与 nginx 对照

对照使用工作区正式binary：`rut --backend epoll`，无 RUT_STUDY 环境变量。nginx固定1.29.7镜像。proxy_buffering off；原配置proxy_buffer_size16KiB，调优配置proxy_buffer_size256KiB、proxy_buffers8×256KiB、proxy_busy_buffers_size256KiB。短连接双方关闭origin复用，nginx显式keepalive0并验证origin连接ID均不同；长连接nginx显式keepalive4096并验证复用。每个配置2轮、5s预热+20s测量。

| c128 场景 | Rut epoll RPS | nginx16KiB RPS | nginx256KiB RPS |
|---|---:|---:|---|
| close | 2720.1 | 1598.1 | 3081.2 |
| keepalive | 3003.2 | 1561.1 | 未形成稳定双轮：1有效/3无效（单有效轮3539.9） |

Rut超过此处nginx16KiB配置；nginx也扩大buffer后，短连接仍比Rut快。nginx256KiB长连接首批2轮分别4/5次timeout；独立复测1轮零错误、约3540RPS，另1轮4次timeout。所有无效数据完整保留，不能把失败轮次平均为有效性能结果，也不能把单有效轮当作稳定验收。Rut同期开测8行全部有效。局限于单机loopback、明文、单worker、1MiB streaming，不代表TLS、多核或所有nginx配置。

配置审计更正：删除显式keepalive不能关闭nginx1.29.7 upstream复用；该版本默认keepalive32。此前“matched-close”以及首个workspace对照没有显式keepalive0的结果不用于最终匹配比较，均保留原始证据。参考[nginx官方keepalive文档](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#keepalive)。

## 验证

隔离构建：新增2个epoll_bulk_body测试，152项检查通过；全套网络1584测试、350900检查通过。最初新测试失败发现epoll pool未预留bulk容量，修复初始化后重跑通过。覆盖已缓冲内容、短body/chunked/TLS跳过、部分发送pin、分配失败回退、响应边界归还和关闭回收。

工作区：`cmake --build build --target rut -j2`通过；CLI后端测试通过；实际epoll服务3个短连接+同一长连接10个1MiB响应逐字节校验通过，origin连接ID前三次不同、后十次相同，SIGTERM退出0。相关改动范围clang-format和git diff --check通过。未新增完整ASan/tidy/CI或TLS性能测试。性能结束后运行工作区验证，不与负载重叠。

原始结果、命令、配置（含每组实际nginx配置）、CPU计数、负载监测、验证日志见 evidence.tar.gz。epoll.patch只包含本轮epoll header修改；保留工作区已有其他改动。

## PR 分支验证

基于最新 origin/main fbb37d3c 的独立 worktree，Release/O2、RUT_ENABLE_JIT=OFF：rut 和 test_network 构建通过；全套网络1562测试、349816检查通过；新增epoll_bulk_body 2测试、152检查通过。之前JIT启用的隔离版本与工作区HTTP验证和性能数据如上，未将其当作最新main的重新性能验收。
