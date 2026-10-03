# 原生 complete-buffered 接收优化：2026-10-03

候选已保留。Sol 负责架构、问题拆解、实现审核和独立数值核验；Luna 负责实现与验证脚本。HTTP 1MiB、并发 32 的吞吐提高 36–48%，p99 降低约 30%，前端每请求 CPU 时间降低 32–39%。该长连接坐标的候选吞吐约为 nginx 的 1.09 倍；短连接仍落后约 9%。不能据此宣称整个矩阵全面追平 nginx。

## 改动与合同

已确认 Content-Length 完整缓冲条件后，后续正文通过 io_uring one-shot recv 直接写入 `ResponseBodyChain` 尾节点。头部与首段正文仍使用独立的 provided-buffer ring。整个候选同时改变接收策略并减少缓冲复制，未做消融实验，因此收益不能单独归因于消除 memcpy。

每次直接接收保存不可变的节点、地址、长度和 upstream episode 所有权；关闭后保留缓冲直到对应 CQE 终结。逻辑提交与物理写入分开记录，过期或超长写入不发布，并在释放时清零。接收保留边界外一个字节的观测空间，保持超长正文拒绝合同；未使用 MSG_WAITALL，保持正向接收推进与 inactivity deadline 的关系。

性能测试使用 `.completeContentLength`。当前 `.bounded` 是同一完整缓冲实现的别名，流式 bounded 能力仍标记待实现；本次仅补别名正确性验证。`None` 流式模式及 epoll 接收逻辑未改变。未新增语言关键字、依赖、分配器或 eBPF 数据面路径。

## 为什么大响应收益明显

旧路径的正文接收目标是 16KiB provided buffer，每个有效接收完成后再复制到响应缓冲链；新路径在条件确认后由内核直接写入链的尾节点，跳过这次用户态复制。已有 bulk 节点约 256KiB，直接接收也能够利用更大的剩余空间。这里改变的是接收目标与单次接收上限；实际读取大小、CQE 次数和 cache 行为没有计数，不能宣称完成事件减少了固定倍数。

1MiB、并发 32 下 CPU/请求显著下降，与省去重复搬运及事件处理成本的解释相符；大于约 16KiB 的接收空间也可能改善事件批次和推进效率。c1 的吞吐近中性、小响应 CPU 微升，说明收益受并发和固定开销影响。one-shot 的主要作用是提供安全的自然终结交接，它本身并不保证更快；需要消融和 profiling 才能区分复制、接收粒度与排程各占多少收益。内核仍将 socket 数据复制入目标缓冲，释放时清零仍然存在，这不是零复制网络栈。

## 性能结果

四组顺序为 baseline → candidate → candidate → baseline。每个变化栏分别列出正向 candidate/group1 对 baseline/group0，以及反向 candidate/group2 对 baseline/group3。每组每坐标每引擎重复三次，取中位数；最后一栏为两组候选各自相对同组 nginx 的吞吐比值。CPU 指前端进程 CPU 时间/请求，非整个机器或 origin 的 CPU。

| 场景 | 并发 | 连接 | 吞吐变化（正向 / 反向） | p99 变化 | CPU/请求变化 | 候选/nginx 吞吐 |
|---|---:|---|---:|---:|---:|---:|
| HTTP 1MiB | 32 | 短连接 | +36.07% / +37.13% | -30.17% / -30.22% | -31.52% / -32.42% | 0.905 / 0.907 |
| HTTP 1MiB | 32 | 长连接 | +48.27% / +45.37% | -29.16% / -30.08% | -38.59% / -37.10% | 1.094 / 1.090 |
| HTTP 1MiB | 1 | 短连接 | +1.06% / -0.15% | -3.32% / -2.06% | -8.40% / -8.99% | 0.703 / 0.711 |
| HTTP 1MiB | 1 | 长连接 | +1.50% / +1.49% | +0.30% / -3.57% | -8.46% / -7.91% | 0.899 / 0.905 |
| HTTP 1MiB | 128 | 短连接 | +3.76% / +2.79% | -12.78% / -17.15% | -4.55% / -2.17% | 0.700 / 0.696 |
| HTTP 1MiB | 128 | 长连接 | +10.72% / +14.05% | -21.78% / -23.56% | -11.93% / -15.53% | 0.952 / 0.985 |
| HTTP 64KiB | 1 | 短连接 | +0.22% / +0.82% | +0.00% / -2.14% | +1.13% / +0.89% | 0.904 / 0.903 |
| HTTP 64KiB | 1 | 长连接 | +1.10% / +1.36% | -1.64% / -2.70% | +0.47% / +0.22% | 0.901 / 0.901 |
| HTTPS 1MiB | 128 | 短连接 | +4.89% / +5.20% | -5.04% / -5.74% | -5.39% / -5.59% | 0.949 / 0.924 |
| HTTPS 1MiB | 128 | 长连接 | +10.69% / +10.47% | -14.44% / -13.61% | -10.85% / -10.54% | 0.973 / 0.974 |

240 个正式样本全部有效，warmup 和正式请求错误均为零。c1 的吞吐接近持平但 1MiB CPU 降低约 8–9%；64KiB 吞吐接近持平，CPU/请求反而小幅增加约 0.2–1.1%，不宣称其稳定收益。TLS 短连接吞吐改善约 5%，但候选请求 p99 仍约为 nginx 的 16.5–16.8 倍；wrk 请求延迟不包含完整连接建立及 TLS 握手，不能解释为端到端握手延迟已改善。TLS 短连接第一对 nginx 有漂移，原始与归一化结果均保留。

## 方法与来源

- Linux，Release 实际编译参数 `-O2 -DNDEBUG`，JIT 开启、IPO 关闭、eBPF 关闭。CMake cache 的旧 O3 字段不是实际编译命令；保留选取的 compile_commands 作为依据。
- 单 worker/shard，Rut 日志确认 io_uring；server CPU 2、origin CPU 3、clients CPU 4/5，使用不同物理核。未锁频，宿主机非独占。
- 使用已有固定 nginx 镜像与仓库 `scripts/nginx_benchmark/run.py`，HTTP/1.1，converter-strict，完整缓冲响应，关闭 upstream reuse。每次 warmup 1 秒，正式测量至少 5 秒；每组和重复交替引擎先后顺序。负载串行执行。
- 四套实验 primary 48、concurrency 96、small 48、tls-r2 48，共 240 条；10 个不同坐标。原始数据、计划、环境、命令、摘要和状态保留供复核。
- baseline HEAD 为 `1e460cf7a9b0a5d69640de50b7ee5f8e7eddf730`，工作树已有先前实验改动；这不是干净提交的基线。两套冻结构建共享这些改动，差异限定为本次七个文件；生产源文件在测量后未变，保留候选 patch 与 hash。
- 首次 TLS 尝试因实验复制证书继承 SELinux 标签而在 nginx readiness 前失败，未产生样本。仅修复实验目录文件标签后以 tls-r2 重跑；失败证据单独保留，不混入正式结果。使用已有 BoringSSL 测试证书，没有新增系统 OpenSSL 依赖。

## 正确性与静态检查

6 个相关 CTest 全部通过：network、arena、native_program、native_protocol、serve_loader、harness。network 首轮 1528 passed、348163 checks，1 项因 io_uring 临时不可用跳过；随后该目标单独复跑 1 passed、9 checks，其余 1528 为过滤项。Arena 68 passed、1,073,620 checks；benchmark harness 33 个测试通过。

真实内核对抗测试在同一服务进程内执行 exact → surplus → exact 三轮，完整模式和 bounded 别名分别测 baseline/candidate，共 36 例全部通过。header 后分段发送至 N−1，静默窗口确认无下游输出；最后一次写入精确最后字节或包含多余字节，origin 保持打开以排除 EOF 混淆。精确正文校验长度与 hash；超长正文输出零字节后关闭，后续正常请求成功。单元测试另覆盖非均匀正文、过期 CQE、关闭/取消与物理脏字节回收。

受影响文件格式检查、git diff --check、三个实验 Python 脚本语法检查通过。backend 与改动行范围 clang-tidy 返回 0，但存在非致命风格警告；扩大 main/header 检查返回 1，原因是既有 `alloc_h2_impl` derived-method-shadowing-base-method 错误，未报告为全量通过。

## 证据与限制

[证据归档](evidence.tar.gz)（[SHA256](evidence.sha256)、[文件清单](archive-manifest.json)）保存原始样本、摘要、环境/命令、测试与接收日志、候选 patch 和源码/二进制 SHA256；排除私钥、证书、正文 payload 和二进制。原始实验工作目录为 `/home/hurricane/private/code/rut-native-opt-20261003`，冻结二进制仍保存在该目录的 baseline/candidate。

未重跑整个 96 坐标矩阵，未验证真实 NIC/RTT、HTTP/2、多 shard、epoll 性能、ASan、全仓库测试或全量 tidy。没有 syscall/CQE 计数或硬件 profiling，无法证明具体内核瓶颈或硬件极限。此结论仅支持保留本次完整缓冲接收候选，并继续按弱项分别验证。

## PR 隔离验证

创建 PR 时从最新 main（`f7cb12fc`）建立独立分支，仅复制七个源码/测试文件与本报告。候选生产源码与性能测量 SHA256 一致，main 上这些文件的基线与实验基线一致。C/C++ 均使用 Clang，Release O2、JIT ON、IPO OFF；主程序及相关测试重新构建成功。独立分支的 6 个 CTest 全部通过，network 1529 passed、348172 checks、无跳过，Arena 68 passed。受影响文件格式及 diff 检查通过。见 [测试日志](isolated-main-ctest.log) 与 [验证记录](isolated-main-validation.json)。独立分支未重新跑性能实验，性能数字仍来自前述冻结 ABBA 构建。
