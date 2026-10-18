# Sidecar 内核正文搬运对照 · 2026-10-03

**1 MiB 明文长连接透传值得继续做 splice 接入实验。** 在共享网络命名空间的两个容器中，同一个 relay 从 recv/send 切换到 splice，反转测量顺序后仍提高吞吐并降低每 GiB 正文的 relay CPU 时间。本轮验证的是独立 TCP relay 机制，未修改 Rut 生产数据路径，也没有加载 eBPF。

## 主结果

双方均开启 `TCP_NODELAY`，每次搬运最多 64 KiB。每组每引擎三轮；以下为三轮中位数。1 MiB 分别运行 copy 先测和 splice 先测两组，组内每轮交替顺序。64 KiB 是补充坐标，仅运行一组。

| 正文 | 并发 | 起始顺序 | copy → splice req/s | 吞吐变化 | relay CPU 秒/GiB 变化 |
|---|---:|---|---:|---:|---:|
| 1 MiB | 1 | copy 先测 | 2,445 → 3,224 | +31.86% | -42.66% |
| 1 MiB | 1 | splice 先测 | 2,674 → 3,246 | +21.41% | -34.85% |
| 1 MiB | 32 | copy 先测 | 2,814 → 3,998 | +42.10% | -41.79% |
| 1 MiB | 32 | splice 先测 | 2,727 → 3,751 | +37.55% | -41.86% |
| 64 KiB | 1 | copy 先测 | 12,258 → 13,246 | +8.06% | -31.20% |
| 64 KiB | 32 | copy 先测 | 34,684 → 37,124 | +7.04% | -30.27% |

36 个主结果样本及全部预热无 wrk 网络、超时或状态错误。18 个前端均通过独立完整正文预检，包括慢读者及后继响应、100 次同连接请求和上游连接计数连续性校验。完整 RPS、p50/p95/p99、relay 用户态/内核态 CPU、origin CPU 和 RSS 见 [results.json](results.json)、[summary.json](summary.json)。CPU 秒/GiB 为每轮 `(utime + stime) / (完成请求数 × 正文大小 / 2^30)` 后取中位数；包含 HTTP 头和连接成本，分母只计算已完成的响应正文。

1 MiB copy 的 relay CPU 占用中位数约 60%–68%，splice 约 46%–56%；吞吐同时更高，所以每 GiB CPU 降幅比单看占用百分比更大。不同起始组的吞吐幅度有波动，没有计算统计显著性。64 KiB 的结果不能代替两种顺序的复测。此实验同时改变了内核搬运和由此产生的发送行为，不是纯 memcpy 指令周期对照。

## 容器与测量条件

- Linux、HTTP/1.1 隐式 keepalive、固定 nginx 1.29.7 镜像。origin 单 worker，CPU 3；relay 单 worker，CPU 2；wrk CPU 4/5。CPU 拓扑与来源见各组环境记录，没有独占整机或锁频。
- origin 和 relay 是两个容器，relay 使用 `--network container:<origin>`。客户端从宿主通过 Docker 发布端口进入 relay，relay 到 origin 使用命名空间内的 localhost。每个前端都核对了两容器的 netns inode。该布局模拟 Pod 共享 netns；未在 Kubernetes/CNI 中测量，Docker 端口转发成本和节点其他 CPU 成本未归入 relay CPU 指标。
- relay 使用 UID/GID 65532，`--cap-drop ALL`、`no-new-privileges=true`、默认 seccomp。逐前端确认 `CapEff=0`、`NoNewPrivs=1`、`Seccomp=2`，说明本环境无需额外 capability 即可使用 splice；不代表其他容器策略一定允许。
- 1 MiB 每轮预热 2 秒、正式测量 8 秒；64 KiB 预热 1 秒、正式测量 5 秒。每轮先验证正文，再测并发 1、32，沿用同一个前端进程；每个前端结束均检查干净退出和 setup failure 为零。所有命令见 [plan.json](plan.json)、执行状态见 [control-status.json](control-status.json)。
- relay 是相同状态机的两种模式：copy 使用 SlicePool bulk 缓冲中的前 64 KiB；splice 使用每方向一个 64 KiB 非阻塞 pipe。二者共同维护背压、半关闭、连接 generation、错误处理和回收。只透传字节，没有 HTTP 路由、头重写、TLS、body 检查、deadline 或策略执行，不能把相对 copy 的收益称为相对当前 Rut 的收益。
- 为在已有 nginx 镜像运行宿主构建的探针，只读挂载匹配的 libc 和 ELF loader；没有安装包、拉取镜像或新增 C++ 标准库依赖。最终探针 `ldd` 仅依赖 libc 和 ELF loader，构建命令及冻结二进制/库哈希见 [provenance.json](provenance.json)。SELinux 只给本实验专用副本与输出目录设置 container_file_t，没有重标记系统库。

## 复测、内存及计数边界

初始探索轮没有设置 `TCP_NODELAY`，后来查到 Rut 的 socket 设置开启此选项，因此统一开启后完整重测，主结果只取重测。初始数据保存在归档的 `exploratory-tcp-default/`，不混入主结果。第一次 copy 冒烟继承 nginx 镜像的 SIGQUIT 停止信号，而探针处理 SIGTERM，因而容器最终被强制停止；之后显式设置 `--stop-signal SIGTERM`，重跑冒烟和正式对照均正常清理。失败记录也保留。

进程 RSS 不含内核 pipe/socket 内存。每轮 wrk 结束后通过 `memory.stat` 保存容器内存观察，采样包含短暂的 docker exec 进程，且此时压测连接已结束；不能用它宣称活跃峰值内存降低。每个活跃连接预留两个 64 KiB pipe，实际页面占用和归属还需在持续负载期间测量。

停止时记录的 reads/writes/waits/events 计数包含预检、预热、压测及结束阶段。splice 的调用次数并未显示减少，不据此声称免除用户态唤醒。`io_failures` 有非零总计数，客户端 reset/中止会增加这一计数；由于未做分阶段 syscall trace，不能仅凭累计值确定发生时间或全部原因，也不能与 wrk 测量窗口的错误字段混为一谈。此处没有声称全部底层 I/O 错误为零；正式窗口无 wrk 错误及预检成功的范围如上。

## 验证与下一步

- 探针构建成功；最终构建与测量冻结版本逐字节一致。
- [CTest](final-ctest.log) 与 [check target](check-target.log)均通过。两项黑盒测试对 copy/splice 都验证了：持续连接、二进制正文、慢读者背压、半关闭后排空、reset 后后继连接、上游连接拒绝后恢复，以及 socket/pipe FD 回收。
- [基准工具 33 项自测](harness-tests.log)通过；Python 语法检查、clang-format、`git diff --check` 通过。
- [定向 clang-tidy](final-tidy.log)的 bugprone/performance 错误门禁通过，仍有 include-cleaner 和已有 SlicePool 风格告警。未运行全量 CTest、全量 tidy、io_uring splice、TLS、HTTP/2 或长期稳定性测试。

下一步可给 Rut 已有**明文流式、已知 Content-Length、无正文检查/改写**的 forward 路径做隔离 splice 候选。先证明已预读前缀与内核流的衔接、正文边界、超时、取消、异步所有权和回收，再与冻结 Rut 基线做同条件对照。不能直接替换完整缓冲模式；该模式仍需保持完整接收后才发送的现有契约。

用户提出的编译器/eBPF 分工是另一个阶段：编译器静态证明可下沉路径，eBPF 根据实际流量执行判定，Rut 控制组件负责配置版本、socket 映射和上游管理，用户态运行时保留其他路径。内核 sockmap 有 stream parser/verdict 和 socket 重定向能力，但需要已有 socket 的映射与正确流边界。[内核 sockmap 文档](https://docs.kernel.org/bpf/map_sockmap.html) 本轮只验证了内核搬运的性能价值，没有实现这种编译分流或验证策略等价。

[复现说明](../../../scripts/kernel_relay_benchmark.md)、[探针源码](../../../bench/bench_kernel_relay.cc)、[runner](../../../scripts/kernel_relay_benchmark.py)、[黑盒测试](../../../tests/test_kernel_relay.py)。[evidence.tar.gz](evidence.tar.gz) 保存生成配置、确定性正文、逐前端隔离证明、完整预检、origin reuse、wrk/CPU、容器内存和清理计数日志，不包含可执行文件或系统库副本。

后续 [eBPF bytecode 与能力验证](../ebpf-capability-2026-10-03/README.md) 覆盖直接发射、权限、限定 body 边界和回退；不代表 Rut 编译器已支持 eBPF。
