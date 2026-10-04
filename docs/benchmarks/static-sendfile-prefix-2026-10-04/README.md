# 本地静态响应首段复制优化：2026-10-04

保留 io_uring 明文 sealed-memfd 静态正文在 header 完成后从偏移 0 发送的优化。64 KiB 长连接响应在正向与反向对照中，吞吐提升 5.5–12.4%，每请求服务器 CPU 时间下降 12.6–14.6%，P99 下降 5.4–11.6%。1 MiB 吞吐没有明确提升；不能据此宣称所有正文尺寸或整个性能矩阵均改善。

## 实现与生命周期

原路径将约 16 KiB 正文前缀复制到 header 的发送缓冲，再由 sendfile 发送余下文件；候选仅在支持 submit_send_file 的后端、非 TLS、分段正文且有效 memfd/data 时跳过前缀复制。header-only 格式化仍由 segmented_body 控制，TLS、epoll、无文件和小正文沿用原路径。无新依赖、字段或分配。

首 header 提交前设置完整正文 cursor/remaining，使首发与部分 header 续发保留 MSG_MORE。正文使用现有 sendfile offset、partial/POLLOUT、失败后的内存回退与关闭流程；配置 epoch 持有到正文发送结束。Sol 审查生产/测试改动并独立核算数据，Luna 实现。

## 性能结果

每种正文尺寸按 baseline → candidate → candidate → baseline 测量。每组、每并发、每引擎重复三次，表格使用各组中位数，变化为正向 candidate1/baseline0 与反向 candidate2/baseline3。CPU 是服务器进程 CPU 时间/请求。

| 正文 / 并发 | 吞吐变化（正向 / 反向） | P99 变化 | CPU/请求变化 |
|---|---:|---:|---:|
| 64 KiB / 1 | +5.77% / +5.52% | -5.41% / -5.41% | -13.50% / -12.56% |
| 64 KiB / 128 | +12.38% / +10.70% | -11.59% / -10.76% | -14.57% / -13.84% |
| 1 MiB / 1 | -0.18% / -1.05% | +7.77% / +8.19% | -9.75% / +15.71% |
| 1 MiB / 128 | +0.96% / -1.44% | -0.43% / +2.40% | -3.15% / -3.60% |

64 KiB 合并六个基线/六个候选样本的中位数：c1 为 30122 → 31874 RPS，c128 为 89893 → 100263 RPS；CPU/请求分别 13.285 → 11.555 μs、7.770 → 6.664 μs。对应同组同重复 nginx 的吞吐比值中位数为 c1 1.025 → 1.085、c128 1.389 → 1.571，收益方向一致。

1 MiB c1 CPU 两方向反号，不声称稳定收益。其合并 P99 为 294.5 → 310 μs，同组 nginx 归一化 P99 比值为 1.110 → 1.067；宿主机漂移不能被排除，也不能将原始尾延迟上升隐藏。1 MiB c128 CPU/请求合并下降约 3.4%，吞吐合并下降约 1.2%，P99 合并上升约 1.5%。保留依据主要是 64 KiB 可重复收益。

96 个正式样本全部有效，正式与 warmup 错误均为零；每轮完整响应与多次长连接预检通过。测量使用实际 io_uring，日志确认一 shard。

## 构建与验证

基线从干净 origin/main `432b897ad76ec1df48919f16966872cae9c69d92`（PR #768 合并）建立独立 worktree；候选相对该基线仅改变两个源码/测试文件。冻结后串行测量，未使用原工作区的脏改动。Release O2、Clang、JIT ON、IPO OFF，同一 CMake 配置。二进制 SHA256 与候选 patch 位于证据中。

- 聚焦 network 测试：41 passed，808 checks，无失败；其余 1515 项为过滤项。
- 完整 network：1556 passed，349402 checks，无失败或跳过。
- 新回归检查非均匀 64 KiB 正文全量字节、header-only framing、local_response_size、partial header 与 MSG_MORE、epoch、pipeline/accounting。既有测试覆盖文件发送关闭/回退/生命周期，以及 TLS continuation 和无文件正文。
- 两个受影响文件 clang-format dry-run 与 git diff --check 通过。

使用仓库 scripts/nginx_benchmark/run.py 与已有固定 nginx 镜像、wrk/BoringSSL 客户端；HTTP/1.1 native-body static-keepalive。server CPU 2、origin CPU 3、clients CPU 4/5；每样本 warmup 1 秒、正式 5 秒，交替引擎先后顺序。未锁频，宿主机非独占。通过 docker 组访问既有 daemon；实验目录设置容器可读 SELinux 标签。

## 证据与范围

[归档](evidence.tar.gz)及[校验值](evidence.sha256)保留样本、预检、命令、环境、日志、patch、源码构建来源和二进制 hash；[归档清单](archive-manifest.json)与[中位数摘要](summary.json)可直接复核。二进制及原始运行目录另存于 `/home/hurricane/private/code/rut-perf-runtime-next-evidence`。归档排除二进制、payload、私钥及证书。

这是 loopback、单 shard、两个正文尺寸和两种并发的局部实验。未重跑全矩阵、真实 NIC/RTT、多 shard、epoll/TLS 性能、HTTP/2、ASan、全仓库测试或全量 clang-tidy；未做 syscall/CQE 或硬件计数 profiling，不把测量解释为内核层全面零复制。未推送或合并。
