# Proxy 路径优化实验（2026-10-06）

## 最终选择

只保留 splice 首次创建 pipe 时消除重复 F_GETPIPE_SZ 的小改动。F_SETPIPE_SZ 已返回实际容量；检查其返回值即可保留原有容量要求和失败回退。每个新建 relay 少一次 fcntl，不影响复用现有 pipe 的请求。没有证明可测的端到端吞吐或 p99 提升。

- 透明明文：保留现有 splice 和公平性调度。批次末尾直接推进的实验未证明稳定收益，撤回。
- bounded 用户态路径：保留直接接收至正文缓冲区、原地发送与 origin 复用，没有重新启用 SEND_ZC。
- 完整缓冲：现有 buffered_response_bulk_after() 已在 Buffering 阶段为大明文正文返回 0；实验中扩展 bulk 条件是行为等价改动，撤回。该路径数据只能作为对照，不能声称测到了 bulk 优化收益。
- TLS、小正文和 sendfile 路径未修改。SEND_ZC 双完成生命周期仍需独立设计和真实网络验证。

[F_SETPIPE_SZ 接口说明](https://man7.org/linux/man-pages/man2/F_GETPIPE_SZ.2const.html)明确其成功结果是实际容量。

## 被撤回的候选测试

基线 5b8392577f52886deda2a62743d84fc4eb8b27b3，基线 rut SHA256 bdf874f125a264d0a794245095f689f0c8de5caeea884889d23791020c4f68bd。候选补丁 rejected-candidate.patch；候选 rut SHA256 58ca5d452efb4a2bd1cd663fbc5ad3b6ede78df6994b99f137951345e2282bb0。表格数据属于被撤回候选，不是最终小改动的性能数据。

1MiB HTTP；单 worker/shard；服务 CPU0、origin CPU1、客户端 CPU4/6；每格 2 次，每次预热 2s、测量 5s。两版本组内交替 Rut/nginx 顺序，版本组顺序是 baseline 后 candidate，不是 ABBA。短时本机测试不足以给出小幅变化的统计保证。没有并行编译压测；候选测试期间做过短暂格式检查。

native 两侧 origin 复用开启、nginx buffering off；bounded 两侧 origin 复用开启、nginx buffering on；strict 两侧 origin 复用关闭、nginx buffering on。只能在同一 profile 内比较修改前后，不应跨 profile 归因。96 个样本全部 valid，预热和测量错误均为 0；native 运行日志确认有实际 relay admissions。

| 路径 | 连接 | 并发 | 基线 RPS | 候选 RPS | 基线 p99 ms | 候选 p99 ms |
|---|---|---:|---:|---:|---:|---:|
| native-streaming | close | 1 | 2519 | 2507 | 0.448 | 0.495 |
| native-streaming | close | 128 | 2043 | 2029 | 68.496 | 68.097 |
| native-streaming | keepalive | 1 | 2859 | 2844 | 0.459 | 0.458 |
| native-streaming | keepalive | 128 | 2943 | 2971 | 54.132 | 53.975 |
| converter-strict | close | 1 | 1398 | 1341 | 0.815 | 0.902 |
| converter-strict | close | 128 | 1596 | 1583 | 85.836 | 87.242 |
| converter-strict | keepalive | 1 | 1742 | 1753 | 0.722 | 0.732 |
| converter-strict | keepalive | 128 | 1722 | 1740 | 80.135 | 79.541 |
| converter-bounded | close | 1 | 2199 | 2178 | 0.517 | 0.517 |
| converter-bounded | close | 128 | 2109 | 2130 | 70.245 | 69.393 |
| converter-bounded | keepalive | 1 | 2504 | 2486 | 0.513 | 0.526 |
| converter-bounded | keepalive | 128 | 2290 | 2296 | 61.873 | 62.480 |

被撤回候选网络测试：1576 passed，350648 checks，零失败；定向测试 7 passed。最终版本验证另见 final-validation.txt。没有新的 sanitizer 或完整 clang-tidy 验证。

首次两次预跑因缺少配套编译器、编译指纹不匹配未启动成功，没有纳入数据。正式基线与候选各自配套 rut-compile；运行二进制单独保存，不受之后源码回退影响。

原始命令、环境、结果、日志和脚本保存于 evidence.tar.gz；最终保留的源码补丁为 retained.patch。未推送或合并。
