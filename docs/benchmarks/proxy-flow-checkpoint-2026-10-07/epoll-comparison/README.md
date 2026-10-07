# 保留的 io_uring 版本 vs 当前 epoll（2026-10-07）

## 提交和持久保存

旧原型已单独提交为 `b4d350aa`，分支 `experiment/proxy-flow-checkpoint-20261007`，worktree `/home/hurricane/private/code/Rut-proxy-flow-checkpoint`。以原验收patch恢复源码；保留正文缓存复用、完整已发布节点合并、仅关闭请求直接发送、自适应bulk cache及相关实验开关/计数器。SEND_ZC、对齐等失败实验仍不启用。该提交为实验检查点，不是把整套原型自动启用到主工作区。

原始验收二进制、配套compiler helper及当前epoll二进制的冻结副本，已保存到 `/home/hurricane/private/code/rut-performance-checkpoints/proxy-flow-20261007`。旧rut sha256 `0e8b7a2aac39bb80cdb44b8d5840a1ef62cc47b5be53bb977a7d105b4a061e7d`，比较前后均核对；不会拿另一版本或重新构建的binary冒充原验收binary。此源码检查点尚未重建，原测试日志、命令、二进制来源和校验值一并保存。当前epoll修改未被覆盖。

## 同负载版本对照

1MiB明文HTTP、native-streaming、worker/shard1；frontend CPU2、origin CPU3、clients5/7。两版本交替顺序；预热5s，c128测量20s，c1测量10s，每组2轮；高并发长连接另做同条件双轮复测。两个版本各自使用保存的matching compiler helper。旧io_uring自动选择后端并逐组核对日志；新epoll wrapper显式 `--backend epoll`。新版本清除全部RUT_STUDY开关，旧版本启用原候选环境，关闭SEND_ZC和对齐。短连接双方均随下游关闭origin；长连接预检确认origin复用。

这是不同源码版本的整条路径比较，不能归因于纯epoll/io_uring API差异。旧改动最初验收是converter-bounded+origin-reuse；epoll不支持其显式deadline能力，所以本次使用native-streaming，旧body-chain/direct-send实验可能未命中该路径。原bounded验收报告单独保留。

| 并发 | 连接 | 当前epoll RPS | 旧io_uring RPS | 结论 |
|---|---|---|---|
| 128 | close | 2742.4 | 2129.5 | epoll吞吐约高28.8% |
| 128 | keepalive | 3003.9 | 有效轮 3174.7–3178.9；2/4轮无效 | 旧版本未稳定通过；不能用过滤后的均值宣称获胜 |
| 1 | close | 2560.8 | 2575.3 | 基本持平，样本不足以解释小差异 |
| 1 | keepalive | 2993.9 | 2972.6 | 基本持平，样本不足以解释小差异 |

高并发短连接epoll p99约47.5–47.8ms，旧io_uring约62.9–63.6ms。高并发长连接初测旧io_uring第二轮9次timeout；独立复测第一轮5次timeout。其余两轮有效，p99约51ms；epoll本次四轮全部有效。所有无效行完整保留，不混入有效性能均值；summary中的有效轮均值是描述数据，稳定结论必须看stable_pair。

本次20行18有效2无效（均为旧io_uring高并发长连接），有效行预热/测量错误均0，响应预检均通过。TCP计数为宿主累计计数差，复测同时保存，不能直接归因于单个服务。timeout原因未定位；此前当前版本epoll也有一轮6次timeout，证明不能凭本次清洁结果声称永久无此问题。

p99以逐轮值保存，不合并请求分布；结束RSS不是峰值或纯idle值。没有补做TLS、多worker、跨主机、完整CI或新源码检查点重编。负载期间无编译进程监测命中。原证据见evidence.tar.gz，原优化验收见独立worktree的 docs/benchmarks/proxy-flow-checkpoint-2026-10-07。
