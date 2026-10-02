# 编译器子进程拆分验证 · 2026-10-02

用户运行 `rut --compile app.rut --shards 4`。Rut 自动执行同目录的 `rut-compile`，通过管道接收带构建指纹的 native image，等待编译器退出，再加载匿名 sealed memfd 中的代码和配置。原有 `rut app.rut` 也自动完成此流程。无持久化生成库需要管理；部署时两个可执行文件必须匹配。启动环境需要 LLVM 和 CMake 记录的 C 编译器/链接器，服务阶段不加载 LLVM。

## 有限性能复测

这些测量在创建 PR 前、基于 `e54b32bc` 的工作树完成。PR 随后更新到
`c52392c8` 的 main；没有重跑性能矩阵，因此下面数值不代表更新基线后的 PR 版本。

基线是 `e54b32bc` 的冻结可执行文件；候选是当前未提交拆分实现，哈希见 [provenance.json](provenance.json)。Linux、单 shard/worker，前端 CPU 2、上游 CPU 3、客户端 CPU 4/5，HTTP/1.1 隐式 keepalive、1 MiB 正文、并发 32；固定 nginx 镜像与之前主矩阵一致。每个场景/引擎三轮，每轮预热 1 秒、测量 5 秒。两版按先基线后候选测量，各自 Rut/nginx 轮次交替顺序；不是统计显著性实验。

| 场景 | Rut req/s 中位数（拆分前 → 后） | Rut RSS MiB 中位数（前 → 后） | nginx req/s（候选组） |
|---|---:|---:|---:|
| 静态长连接 | 8765 → 8695 (-0.8%) | 77.6 → 20.8 | 9713 |
| 完整缓冲代理短连接 | 1585 → 1558 (-1.7%) | 117.8 → 54.4 | 2337 |

24 个正式样本及全部预热无请求错误，响应预检通过。服务进程 RSS 明显下降；短测吞吐变化不足以证明收益或回归。这次拆分没有解决原来的大响应吞吐缺口。只复测以上两个坐标，没有重新运行 96 坐标矩阵，也没有覆盖 HTTPS、epoll 性能、长期稳定性或热更新。

## 正确性验证

- 构建成功。最新相关 CTest 四项全部通过：native program、native protocol、原有 serve loader、access log startup。此前 JIT 测试也通过。
- 新加载器测试覆盖 O0/O1/O2/O3、正则、路由捕获、导入常量、大正文、响应/失败/重定向策略、timer/cache 与 WebSocket handler。编译器退出且源文件删除后仍可执行代码；销毁释放 native library、正则和正文 memfd。
- 黑盒验证显式 flag 与位置参数、缺少 flag 参数、构建不匹配、截断和尾随字节；失败时无遗留编译子进程。实际服务的 `/proc/maps` 不含 libLLVM，含匿名程序 memfd，主线程无子进程。详见 [protocol-tests.log](protocol-tests.log)。
- 全量 CTest 跑过 263 项；修复子进程拆分影响的 I/O gate 预加载探针和启动故障注入测试后，对失败项复测。相关 gate/差分测试通过；仍有 `test_fixture_exact_input_mount_owner` 失败，诊断为容器读取精确输入返回非零（outcome 9），该测试不运行 Rut。原因尚未确认，不能报告全套通过。需要权限的两个 fixture 和缺少环境的 Envoy 测试跳过。日志保留初次失败及复测记录，见 [full-tests.log](full-tests.log)、[rerun-tests.log](rerun-tests.log)。
- 改动文件格式及 `git diff --check` 通过。未运行 clang-tidy，未验证 macOS。

[results.json](results.json) 保存逐样本数据，[summary.json](summary.json) 保存中位数，[evidence.tar.gz](evidence.tar.gz) 包含实际命令、环境、生成配置、正文、预检和 wrk 日志。不包含可执行文件或私钥。之前 main 的全矩阵结果见 [原报告](../nginx-main-2026-10-02/README.md)。
