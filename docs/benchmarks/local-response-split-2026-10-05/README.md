# 严格本地响应仅拆分响应体复制实验：拒绝保留

继全量 direct serialization 被拒绝后，尝试保留热栈上的响应头合成，仅去掉配置响应体 → scratch 的那次复制。新增内部强类型 IncludeBody/DeferBody 与 strict 专用 header helper，严格验证策略、HTTP/1.1 与请求形状，拒绝 HEAD/204/空响应体；带体的非 HEAD 响应先在 scratch 合成 header，再分别将 header/config-owned body 写入同一个 send buffer。容量先扣除 body 长度，header 构建成功后才 reset；异步发送继续只持有完整 send buffer。普通 generic、failure-policy、HEAD、204 和空响应体维持旧路径。仍保留原 16 KiB scratch 栈数组。

最终拒绝保留，已撤回两文件源码及测试，仅提交文档与可复现 candidate.patch；sendfile 与既有静态大响应前缀去拷贝继续保留。独立 worktree 的原始基线是 `bf294100`，其运行时与 `b942014e`/`ebe20ff4` 相同，复用此前冻结的 ebe20ff4 二进制。候选二进制对应 source-freeze/candidate-provenance 记录的两文件补丁与 hash，Release/O2、Clang、JIT ON、IPO OFF，j2 构建。

## 固定测量条件

真实 io_uring、HTTP/1.1、4093 字节 converter return、本地响应/隐式 keep-alive，单 shard/worker。server CPU 2、origin CPU 3（此场景不访问 upstream）、client CPU 4/5；既有 BoringSSL wrk、固定 nginx 对照，无新系统 OpenSSL 依赖。计时期间无构建或测试。所有 64 行测量（16 筛查 + 48 正式）valid，预热/正式 connect/read/write/status/timeout 错误均为零。保存全部样本，不按结果剔除。

## 15 秒筛查

预热 2 秒、15 秒单次，B-C-C-B 四组，起始 engine N-R-N-R。在 c128，两方向原始 RPS 分别 +12.11/+7.16%，CPU/请求 −10.86/−7.05%，合并 RPS +9.59%、CPU −8.99%、p99 −21.29%。但 nginx 配对归一 p99 为 +1.84%，且归一 RPS 在第二方向略负；c1 两方向也相反（RPS −3.25/+1.68%）。这是有望但不充分的筛查，不能把约 10% 当最终收益。完整结果见 screen-summary.json。

## 扩大正式测量

预热 2 秒、每次 7 秒、3 次重复；组顺序 B-C-C-B，起始 engine R-N-R-N，使每个 variant 的起始 engine 均衡。共 48 行，每个 variant/并发有 6 个 Rut 样本。以下为中位数：

| 并发 | RPS：基线 → 候选 | CPU µs/请求 | p99 µs |
|---|---:|---:|---:|
| 1 | 53304 → 52067（−2.32%） | 8.372 → 8.579（+2.46%） | 29.5 → 35.5（+20.34%） |
| 128 | 194164 → 188385（−2.98%） | 3.521 → 3.628（+3.05%） | 789 → 1171（+48.42%） |

两个方向的 c128 RPS 变化为 −2.82/−0.04%，CPU 为 +3.01/−0.56%，p99 为 +47.40/+3.01%；筛查中的一致收益没有复现。c1 首方向 RPS −6.86%、CPU +5.41%，另一方向仅 +1.08/−0.20%，也不稳定。宿主/nginx 有明显时段波动，因此这些百分比不能当精确因果效应量；但按预设“两个方向吞吐/CPU 受益且无尾延迟回退”门槛，该候选不合格。

nginx 配对归一在 c128 的合并 RPS +4.30%、CPU −4.67%，但 p99 +32.83%，不能用 nginx 更慢来覆盖 Rut 自身未复现的收益。完整 raw、配对比值和两方向统计见 summary.json。没有声称减少复制必然加速，也不声称 p99 改善。未采集 cache 硬件计数，无缓存机制因果结论。

## 正确性验证

构建通过，候选 focused 网络测试 38 项/4526 检查、完整网络测试 1559 项/349452 检查均无失败。新增测试覆盖 4093 字节非均匀 body 的 close/keep-alive/部分发送、header helper 拒绝 HEAD/204/invalid 策略、容量不足时不发送且保留旧 dirty sentinel、无效输出缓冲区不计成功。其他既有测试覆盖 HEAD/204/空 body、失败策略、支持的 strict pipeline 清单等。clang-format 与 git diff --check 通过。

冻结基线和候选各执行真实 HTTP/TLS 18 项 wire 检查，四组均通过：完整 body/hash、HEAD 无体且保留 Content-Length、顺序 keep-alive、slow read、RST 后再次响应；12 次 RST 前后 FD 均为 8。显式双请求 keep-alive pipeline 在 converter strict profile 中两版均沿用既有 fail-close/零响应字节，这项仅验证既有边界，不能称该 pipeline 已支持。没有 TLS/epoll 性能结论。

恢复后生产与测试源码等于基线，候选构建产物仅用于实验，没有作为最终交付。未修改原始 dirty Rut 工作区，未 push、未 merge。

## 证据

evidence.tar.gz 包含所有结果、逐次命令/环境、hash/provenance、源码补丁、构建/测试/真实 wire 日志和驱动；evidence.sha256 校验归档，archive-manifest.json 校验每个成员。省略冻结二进制、tmp、正文 payload、static.conf/static.rut、wire.conf/wire.rut、证书与私钥，保留 origin 配置和 wrk 脚本。完整外部证据目录为 `/home/hurricane/private/code/rut-local-response-split-evidence`。上一项全量 direct 失败记录见 ../local-response-direct-2026-10-05/README.md。
