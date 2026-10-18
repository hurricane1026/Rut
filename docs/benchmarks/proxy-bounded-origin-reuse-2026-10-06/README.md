# 1 MiB bounded GET 的 origin 连接复用

2026-10-06。实现提交 `576ae9ff`，分支 `perf/proxy-close-gap-next`，基于 main `cfab9e75`；沿用前一轮直接接收到 bulk 链尾的实现。仅在独立工作树修改，未推送、创建 PR 或合并。

## 实现范围

显式 `.bounded`、明文 HTTP/1.1、depth 0 的无 body GET 可以借用现有 shard 内 upstream pool。请求写完后仍验证当前请求的上传与响应读计时器归属；复用失败不会重放严格策略请求。完整且允许持久连接的响应在 origin 接收所有权结束后可以归还连接池，客户端 `Connection: close` 不再强制关闭 origin。

归还之前检查 Content-Length 完整、没有多余字节或 FIN、没有未结束的接收/取消、配置仍一致且 shard 未进入 drain。仍有 multishot 接收或取消所有权时关闭 origin；此次没有新增跨异步取消的连接移交协议。固定长度请求上传、流水线后继请求、TLS 与默认 `.completeContentLength` 的准入范围保持原样。此次没有增加语法、依赖、堆分配或连接字段。

## 验证

- Clang 22 Release O2、JIT ON、IPO OFF；`rut` 与 `test_network` 构建成功。
- 全量网络测试：1573 项、350095 次检查，零失败。新增测试覆盖复用 GET 的超时 504 与干净/多余字节/FIN/配置变更/仍有接收所有权的归还判定。
- 真实 CLI/JIT 与独立 origin 的七组测试通过：连续请求复用、FIN 后重新建连、截断响应只排空准许前缀、复用后读超时 504、多余字节不污染下一请求、304 元数据响应、空 200。正常响应逐字节核对带块编号的 1 MiB body；origin connection ID 证明复用。
- benchmark Python 35 项通过。首次完整运行在已有进程清理测试的 `/proc` 读取发生进程消失竞态，复跑通过；保留两次日志。
- 受影响 C++ 文件完整 clang-format 检查通过，`git diff --check` 通过。
- 未运行新的 sanitizer / 完整 tidy；未做 TLS、HTTP/2、epoll 性能验收。

## 测量方法

同一候选二进制以 origin 复用关、开、开、关的 ABBA 顺序测量，Rut/nginx 先后顺序交替。每组包括客户端短连接与长连接、并发 1 与 128；每格预热 2 秒、测量 10 秒。单 worker，server CPU 0、origin CPU 1、client CPU 4/6。两引擎使用相同的 1 MiB payload、固定 nginx 容器 digest。origin 关闭复用时 idle timeout 0，开启时 60 秒；nginx 开启组显式配置 upstream keepalive 和 HTTP/1.1。响应缓冲仍为 16 KiB 首缓冲与 8 × 16 KiB body buffers。

开启组的响应预检对客户端短连接和长连接都要求 origin connection ID 相同且请求计数递增。访问日志仅记录带标记的预检请求，不记录压测流量。吞吐和 p99 为每个模式两轮结果的中位数，p99 没有合并原始延迟分布；wrk 请求延迟不包含客户端 TCP 建连。

共享机器仍有其他构建活动；逐核 host ticks 和 server/origin user/kernel ticks 随样本保存。此次开关也改变 origin 与 nginx 对照的持久连接配置，不能把所有性能差异归因于单个 syscall 或仅 Rut 的代码变化。

## 测量结果

配对系列完成了前三组（off/on/on），第三组 Rut 长连接 c128 出现 34 次 wrk timeout，验收失败，第四组未执行。该组不能用于收益汇总，也不能报告为零错误。

| 顺序 / 复用 | Rut 短连接 c128 RPS / p99 ms | nginx 短连接 c128 RPS / p99 ms | Rut 长连接 c128 RPS / p99 ms | nginx 长连接 c128 RPS / p99 ms |
| --- | ---: | ---: | ---: | ---: |
| 1 / off | 1300 / 130.607 | 1673 / 88.527 | 1420 / 102.089 | 910 / 215.406 |
| 2 / on | 851 / 296.737 | 1352 / 161.439 | 1297 / 138.953 | 1328 / 169.452 |
| 3 / on | 1184 / 120.837 | 1708 / 82.705 | 无效：34 timeout，p99 992.989 | 1887 / 938.834 |

开启组的 server/origin SMT 兄弟线程 CPU 8/9 多数接近 100% 忙碌。第三组两个引擎的长连接 p99 都接近一秒；环境干扰明显，但这不能替代排查或消除 Rut 的超时。功能复用已证实，稳定吞吐收益、长连接无退化均未通过验收。后续在同样开启复用的配置上比较运行时优化，保留此次负面样本。

## 证据与复现

原始证据目录 `/home/hurricane/private/code/rut-bounded-evidence-20261006/` 保存配置、命令、原始 wrk 日志、预检、逐核与进程 CPU、二进制 SHA-256、源差异、构建与验证日志、功能测试脚本及测量封装。不包含可执行文件或 TLS 私钥。`origin-reuse-provenance.json` 提供代码提交与二进制 SHA-256；封装调用仓库 `scripts/nginx_benchmark/run.py`，复测时需要调整绝对路径、CPU 与端口。
