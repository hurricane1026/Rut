# sendfile 与 io_uring SPLICE 本地对比：2026-10-04

继续保留 sendfile。实测 io_uring SPLICE 仅在 64 KiB / 128 并发下改善吞吐；另外三个坐标明显回归，尤其 1 MiB / 128 并发的 CPU 成本与尾延迟。实验代码已撤回，保留候选 patch 与全部证据，不推送或合并。此结论针对本次实现与负载，不能泛化为所有 io_uring 文件发送方案。

## 结果

每个正文尺寸按 control → candidate → candidate → control 串行测量，每组重复三次。各版本各坐标六个样本，表格为合并中位数；CPU 为服务器 CPU 时间除以请求数，单位 μs。变化为 candidate/control − 1。

| 正文 / 并发 | sendfile → splice RPS | 吞吐变化 | CPU/请求变化 | P99 变化 |
|---|---:|---:|---:|---:|
| 64 KiB / 1 | 31714 → 27297 | -13.93% | +66.85% | +9.46% |
| 64 KiB / 128 | 101489 → 109429 | +7.82% | -6.46% | -2.87% |
| 1 MiB / 1 | 4479 → 3786 | -15.47% | +304.97% | +7.01% |
| 1 MiB / 128 | 8753 → 7045 | -19.52% | +125.97% | +82.15% |

绝对 CPU/请求与 P99：

| 正文 / 并发 | CPU μs：sendfile → splice | P99 μs：sendfile → splice |
|---|---:|---:|
| 64 KiB / 1 | 11.623 → 19.394 | 37.0 → 40.5 |
| 64 KiB / 128 | 6.600 → 6.173 | 1409.0 → 1368.5 |
| 1 MiB / 1 | 46.720 → 189.203 | 285.5 → 305.5 |
| 1 MiB / 128 | 36.608 → 82.724 | 14394.0 → 26219.0 |

双方向吞吐变化分别为 64 KiB/c1 −13.64% / −14.21%、64 KiB/c128 +7.30% / +8.29%、1 MiB/c1 −15.28% / −15.66%、1 MiB/c128 −20.20% / −18.98%。对应同组同重复 nginx 归一化吞吐变化为 −14.48%、+7.59%、−14.85%、−19.51%，方向一致。1 MiB/c1 原始 P99 两方向反号（−2.26% / +13.70%），不声称该坐标尾延迟变化稳定。完整 raw/normalized/双方向数据见 summary.json。

96 个正式样本全部 valid，测量与 warmup 请求错误均为零；每轮完整响应和 keep-alive 预检通过。早先 small-0-baseline / big-0-baseline 为旧 ebe20ff4 二进制校准，未混入正式 96 个样本。

## 实现与可能原因

A 使用现有 sendfile：可同步发送完成，背压时由 io_uring POLLOUT 续发。B 使用真实 IORING_OP_SPLICE：sealed memfd → 非阻塞 pipe → socket，每段最多 64 KiB；每连接至多一个阶段 SQE 在途，部分写先排空 pipe，发送 EAGAIN 后提交 POLLOUT。统一只发布一个逻辑 Send 完成，配置 epoch 持有至终态，独立 cancel token，回收与 shutdown 显式关闭 pipe。

B 每个 1 MiB 响应约需 16 次 Pull 和 16 次 Push CQE，正式候选日志中 EAGAIN/POLLOUT 均为 0。这与额外阶段/调度成本造成回归的解释一致，但未做内核或硬件计数 profiling，不能将全部差额严格归因于某一项。Linux master 的 io_uring splice 实现设置 REQ_F_FORCE_ASYNC；本机实际出现 iou-wrk 线程，并验证其与主 shard 都限制在 CPU 2。master 代码说明机制，不是本机 Fedora 内核源码逐行验证。

primary sources: [liburing header](https://github.com/axboe/liburing/blob/master/src/include/liburing.h)、[Linux io_uring splice implementation](https://github.com/torvalds/linux/blob/master/io_uring/splice.c)。io_uring SPLICE 需要 pipe 端点；它不是直接把 sendfile 换成同名异步 opcode。

实验开关 RUT_ENABLE_MEMFD_SPLICE 默认 OFF。双方使用相同六个生产/构建文件，只切换开关；控制版也包含相同的状态表和统计字段，避免把布局改变与 I/O 机制混为一谈。setup 或首个 SQE 提交失败且未 Pull 可退回 sendfile；异步 Pull 错误及已 Pull 后错误 fail-close。所有正式候选日志 Pull/Push CQE 均为正，且 setup_failures/pre_pull_fallbacks 为零，证明命中实际 splice 而非 fallback。

正式段结束后关闭尚未完成的请求，会留下 pulled_bytes > written_bytes。已保留 post_pull_failures 和原始日志；该差额与退出期仍活动或终止中的 splice 状态同时出现，不能等同于已完成客户端响应丢字节，也不能从统计中删除。真实完整正文检查和压力测试的 pulled/written 相等。

## 验证

- control/OFF 完整 network：1556 passed，349402 checks，无失败或跳过。
- candidate/ON 新增阶段与取消 focused：2 passed，53 checks，无失败；其余 1556 为过滤项。ON 完整 network 未运行，不将 focused 视为完整回归。
- 双方真实内核 wire-pressure：各 19 项通过，非均匀正文逐字节核对，覆盖 keep-alive、流水线、关闭、慢读、连续八个大响应背压、12 次 RST 后继续请求。candidate FD 为 10 → 10；这只证明该断连检查未观察到泄漏，不证明所有生命周期无泄漏。
- candidate 压力统计：Pull CQE 404、Push CQE 422，pulled/written 均 26476544 字节，Push EAGAIN 9、POLLOUT 9，setup/fallback/post-pull failures 均 0。
- 受影响文件 clang-format dry-run 与 git diff --check 通过。初始测试编译/fixture 失败日志保留；修正仅改变 tests，性能二进制与生产源码 hash 未改变。Sol 审查实现及数据，Luna 实现；root 串行调度所有重编和测量。

## 环境、复现与范围

独立 worktree 基于 ebe20ff4d19c07311fbf037e4a68374823a5dbda（包含此前静态正文首段复制优化），原始脏工作区未改动。Release O2、Clang、JIT ON、IPO OFF；同一 CMake 配置，仅开关不同。冻结 control/candidate 的 rut SHA256 分别为 7379be6de71ea30e9a6cffe63092c34346473d23d554f04da42356e3369bf815 / 3f60d74125760f347f03c057550de056586c31500ea104243afe14ebd24b4602；converter/compiler hash 相同。测试后来独立修正，详细源码 hash、compile commands 和冻结记录见 provenance。

Linux 6.19.10-300.fc44.x86_64；HTTP/1.1 native-body static-keepalive，loopback，单 shard。server CPU 2、origin CPU 3、clients CPU 4/5；warmup 1 秒、正式 5 秒。使用仓库 scripts/nginx_benchmark/run.py、已有固定 nginx 镜像与 wrk/BoringSSL；未新增依赖。计时期间不运行编译或测试。组内重复交替 Rut/nginx 顺序，但 control 首引擎为 nginx、candidate 首引擎为 Rut，因此引擎初始顺序与版本关联；这是双向组顺序对照，并非随机化或严格样本级 ABBA。归一化参照降低漂移影响，不能消除所有顺序偏差。未锁频、宿主机非独占；nginx 作为漂移参照，RSS 只作粗略控制。

本次只比较明文 sealed-memfd 静态响应的两种机制，未验证真实 NIC/RTT、更多正文尺寸、多 shard、TLS/epoll 性能、ASan、全仓库测试或全量 clang-tidy。64 KiB 高并发收益可以作为未来更细选择策略的线索，本次不引入自适应 gate 或改变默认行为。

复现：在 base ebe20ff4 上应用归档 candidate.patch，分别以 -DRUT_ENABLE_MEMFD_SPLICE=OFF/ON 配置构建并冻结二进制，然后按 run_group.py 的精确参数运行 small2/big2 四组；脚本中的绝对路径需按本地目录调整。summarize.py 重算 summary.json。

[归档](evidence.tar.gz)、[校验值](evidence.sha256)、[清单](archive-manifest.json)与[摘要](summary.json)保留正式样本、预检、命令、环境、日志、候选 patch、构建来源和二进制 hash。归档排除二进制、重复 payload/含 payload 的生成配置、私钥及证书；原始完整目录为 /home/hurricane/private/code/rut-sendfile-splice-compare-evidence。
