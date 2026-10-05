# HTTP Date 按线程缓存：2026-10-05

保留严格响应的 HTTP Date 格式化缓存。同一秒内复用线程私有的 29 字节 IMF-fixdate，减少重复 `gmtime_r` 和数字格式化。孤立函数命中从约 38.92 ns/次降到 3.46 ns/次；端到端收益较小，不能将函数微基准的倍数解释为 Rut 吞吐的倍数。

## 实现与语义

`strict_response_date` 仍读取调用者传入的 realtime 时间，以 `now_us / 1000000` 精确匹配缓存。跨秒、时钟回拨和纪元 0 均按实际时间重新格式化；不引入粗粒度计时器或单调时间替代。失败的 `gmtime_r` 不发布新缓存。结果复制到调用者拥有的输出，不借用连接或配置缓冲。

缓存是函数局部、平凡类型的 `thread_local`，二进制符号大小为每线程 40 字节。每 shard 的事件线程独立，无堆分配、共享锁、线程间可变状态或新增依赖。严格本地响应及复用此格式化函数的错误/重定向路径受益；发送与取消、sendfile、后端推进和配置生命周期保持原实现。

生产差异为一个格式化函数；新增两个测试覆盖秒内缓存、调用者覆盖输出、闰日/月/年边界、回拨，以及同时使用不同时间的线程与重复线程生命周期。

## 端到端结果

所有分组依次 baseline → candidate → candidate → baseline，nginx 与 Rut 交替先运行。表格为各版本所有有效样本的中位数，变化为 candidate/baseline。CPU/请求由服务器进程 CPU 时间除以请求数估算；不是硬件计数器。

| 场景 | RPS 基线 → 候选 | 吞吐变化 | CPU/请求变化 | p99 基线 → 候选 |
|---|---:|---:|---:|---:|
| 2 worker / 16 B / c1 / 7 s | 56151 → 56697 | +0.97% | -0.79% | 22 → 22 µs |
| 2 worker / 16 B / c128 / 7 s | 390897 → 395284 | +1.12% | -1.62% | 407 → 386.5 µs |
| 1 worker / 4093 B / c1 / 15 s | 53784 → 54505 | +1.34% | -1.69% | 21 → 21 µs |
| 1 worker / 4093 B / c128 / 15 s | 192063 → 196388 | +2.25% | -2.63% | 745.5 → 782.5 µs |
| 2 worker / 16 B / c128 / 30 s 复测 | 379438 → 391407 | +3.15% | -3.74% | 398 → 363.5 µs |
| 最终命名修正后 / 同场景 / 30 s | 383711 → 391109 | +1.93% | -2.95% | 383.5 → 366.5 µs |

7 秒双 worker 正式实验共 48 样本，每版本/并发有 6 个 Rut 样本。c1 两种顺序吞吐均上升（+0.89%、+0.70%），CPU/请求均下降；c128 顺序结果反号（吞吐 -5.46%、+1.30%；p99 -10.19%、+1.04%），故不依赖这组聚合值认定高并发稳定收益。

4 KiB 的 15 秒补测共 16 样本，每版本/并发只有 2 个 Rut 样本。吞吐两种顺序均提升、CPU/请求均下降；c128 的 p99 为 +12.33%、-2.42%，聚合上升约 4.96%。这是不利结果，不能声称该尺寸尾延迟改善。

针对短窗口波动，追加 8 个 30 秒样本，仅复测 16 B / 2 worker / c128。两种顺序吞吐分别 +4.54%、+1.83%，CPU/请求 -5.02%、-2.41%，p99 -9.13%、-8.16%。同期 nginx 归一化后的吞吐比值变化 +2.02%，CPU 比值 -2.15%，p99 比值仅 -1.56%；宿主机漂移对原始 p99 数字有明显影响。长窗口每版本仅 2 个 Rut 样本，不提供统计显著性或普遍 p99 保证。

最终修正两个局部常量名后重新构建，因二进制哈希不同，额外冻结最终二进制并重新进行 8 个 30 秒样本。最终版吞吐两种顺序 +4.08%、-0.10%（后一种基本持平），CPU/请求 -4.41%、-1.40%，p99 -5.58%、-3.22%；聚合吞吐 +1.93%、CPU/请求 -2.95%、p99 -4.43%。但同期 nginx 归一化后的吞吐比值 -4.01%、CPU 比值 +4.16%、p99 比值 +4.72%，不能忽略。最终小样本仍受宿主机/引擎间波动影响，不能给出稳定的端到端吞吐或 p99 提升保证。

合计 80 个端到端样本均有效，正式及 warmup 的 connect/read/write/status/timeout 错误均为零。保留依据是明确减少重复格式化工作、单连接和较长窗口的吞吐/CPU 收益；不是所有场景尾延迟全面变好。

## 微基准

微基准提取基线/候选函数体，以运行时函数指针选择实现，检查输出 checksum；不包含 `realtime_us`、网络或其他响应处理。单线程 CPU 2，命中每次 500 万调用，ABBA 三轮；不同秒 miss 每次 100 万调用，ABBA 一轮。命中中位数 38.92005 → 3.4593 ns/次（约 -91.1%），miss 为 38.77665 → 43.1198 ns/次（约 +11.2%）。换秒首次调用稍慢，高频请求中同秒缓存命中占大多数；低频负载不能假定受益。

另有双线程、CPU 2/6、每线程 500 万调用、每线程不同秒的 ABBA 对照，聚合 wall ns/次为 59.9703 → 6.95285。它验证独立线程重复格式化的开销下降，不能据此归因某种 libc 锁或宣称多 shard 网络吞吐提高相同比例。

## 构建、验证与边界

基线是最新 main `fe332f6e4b8c3e81d11d38364b50fbb4845df34a`（PR #773 合并）。独立干净 worktree；原用户脏工作区未用于构建或修改。双方使用相同 Release O2、Clang、JIT ON、IPO OFF 配置。先构建基线、再构建冻结候选，并记录源码、patch 和全部二进制 SHA256；整个计时阶段不构建或运行测试。结束后哈希与反向 patch 检查通过。

- 聚焦 network：59 passed / 5210 checks。
- 首次完整 network：1557 passed、1 failed；失败发生在已有 `iouring_episode.invalid_upstream_episodes_do_not_acquire_sqe_or_state` 的 `backend.init`，报 errno 12 / ENOMEM，尚未进入用例路径。完整失败日志保留，不能报告首次测试通过。
- 该初始化用例单独重试：1 passed / 25 checks；随后一次完整重跑：1558 passed / 349641 checks，零失败、零跳过。重试期间源码未修改。
- 冻结基线/候选的真实 HTTP、TLS 1.3 四组 wire 检查各 21 项通过：完整非均匀正文、HEAD、长连接、关闭、慢读、RST 后有效响应、Date 形状/新鲜度/跨秒更新。每组 FD 计数前后均 8 → 8。TLS 使用现有 BoringSSL 服务端和既有证书夹具；仅检查正确性，没有 TLS 性能结论。
- 显式连续 double GET pipelining 仍是已有不支持边界，两版本均以零响应关闭；不能把该检查解释为实现了 pipeline。
- 两个受影响文件 clang-format dry-run、git diff --check 通过。

最终命名调整只是自动局部常量 `second/len` → `kSecond/kLen`，源码/patch/binary 哈希另存 `final-provenance.json` 和 `final-candidate.patch`，原测量文件均保留。最终聚焦 network 重跑仍为 59 passed / 5210 checks；最终 HTTP 和 TLS wire 各 21 项再次通过，FD 均 8 → 8。完整 1558 项重跑发生在该命名调整之前。

静态分析对 `src/runtime/callbacks.cc` 的最终 TU 返回 1：epoll/iouring 的已有 `alloc_h2_impl` 均触发 `bugprone-derived-method-shadowing-base-method`。将 git HEAD 的基线头文件置于前置 include 目录，以相同编译数据库和参数复查，确认这两个 hard error 完全一致。两个新增的非致命常量命名告警已修正；其他既有非致命告警未做无关修改。`validation.json`、`tidy-final.log` 与 `tidy-baseline.log` 保存完整结果，不声称 clang-tidy 通过。

使用已有 `scripts/nginx_benchmark/run.py`、固定 nginx 镜像与 wrk/BoringSSL 客户端，HTTP/1.1 implicit keepalive / converter-return。双 worker 的服务端 CPU 为 2/6，clients 4/5/8/9；单 worker 服务端 CPU 2、clients 4/5。Rut 与 nginx 每组使用相同 worker 数和服务端 CPU 集合。warmup 均 2 秒；origin CPU 3，静态路径不访问 origin。loopback、未锁频、宿主机非独占，不代表真实 NIC/RTT、HTTP/2、epoll/TLS 吞吐或完整 nginx 对比矩阵。未重跑 GCC/no-JIT/macOS、ASan 或全编译器/JIT 测试；没有 perf 可执行文件，未做硬件计数 profiling。

## 证据

[双 worker 摘要](two-summary.json)、[单 worker 摘要](single-summary.json)、[30 秒复测摘要](confirm-summary.json)、[最终版本摘要](final-summary.json)提供完整中位数、同组同期 nginx 比值与顺序对照。 [完整归档](evidence.tar.gz)、[校验值](evidence.sha256)、[文件清单](archive-manifest.json)保留驱动、命令、环境、全部样本与验证/构建日志、候选 patch、源文件及二进制来源 hash。归档排除二进制、完整响应/正文、生成配置和证书私钥。

本机原始证据在 `/home/hurricane/private/code/rut-http-date-cache-evidence`。本轮本地提交，不自动推送、创建 PR 或合并。
