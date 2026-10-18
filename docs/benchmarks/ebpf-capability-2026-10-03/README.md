# eBPF bytecode、能力探测与分阶段转发验证（2026-10-03）

结论：**直接生成可加载 bytecode、启动时选择内核或用户态路径的机制可行；
目前证据不足以把任意 Rut L7 请求中途移交给 sockmap。** 实验没有修改 Rut
编译器或生产运行时，也没有测得 eBPF 相对 Rut/nginx 的吞吐提升。

上一步 [copy/splice sidecar 实验](../kernel-relay-sidecar-2026-10-03/README.md)
验证了内核搬运收益；本次验证的是 bytecode 加载、权限、请求边界与失败回退。
这是固定模板的 Linux 原型，**不是 `.rut` 到 eBPF 的编译后端**。

## 实现与产物

- [探针](../../../bench/bench_sockmap_probe.cc) 直接构造 eBPF 指令，用 `bpf()`
  加载 parser/verdict、创建 sockmap、挂入两个已经建立的 TCP socket。
  不经过外部 C/BPF 编译器；不新增 libbpf、ELF loader 或 LLVM 运行时依赖。
  可先离线 `emit`，再在另一进程用 `--bytecode` 读取这些文件并重定位加载。
- 构建开关 `RUT_BUILD_EBPF_PROBE=OFF` 默认关闭，只控制实验目标。
  ON/OFF 均验证；OFF 不生成探针或其检查目标。不是生产 `RUT_ENABLE_EBPF`。
- 原型执行策略 `off/auto/required`：禁用；无法加载时撤销部分挂载后回退；
  无法加载时明确非零退出。`required` 要求能力可用，允许单次流量因不满足
  切换条件而走用户态，不要求所有请求都下沉。
- 原始文件使用构建机器的 eBPF instruction ABI；尚无通用版本化包格式。
  两种模板都只接受本探针生成的固定指令。加载前校验完整内容，加载后经过 verifier。
  产物不包含进程 FD；端口和 map FD 在加载时填入。
- [控制脚本](../../../scripts/ebpf_capability_probe.py) 保存命令、退出码、stderr、
  逐次 JSON、内核版本、Docker 镜像 ID 和探针/bytecode/动态库哈希。
  [黑盒测试](../../../tests/test_sockmap_probe.py) 注册至 CTest 和 `check`。

普通 TCP 模板：parser 16 B、verdict 80 B。限定 body 模板：parser 176 B、
verdict 248 B；socket map 与两方向独立的预算 map 分开。
[发射元数据](emission.json) 标明重定位位置。

## 实测结果

内核 `6.19.10-300.fc44.x86_64`，已有本地 `nginx:latest` 镜像。
五种环境各 27 次，加一组保留默认 seccomp 的 27 次，总计 **162 次**。
每组包含 9 个场景，各重复 3 次；最终记录的所有预期行为通过。

| 环境 | 实测结果 |
|---|---|
| 宿主普通用户 | 创建 map 返回 EPERM；auto 完整回退，required 明确失败 |
| UID 65532、无 capability、no-new-privileges、默认容器策略 | 同样 EPERM；auto 完整回退 |
| BPF + NET_ADMIN、默认 SELinux label、默认 seccomp | EACCES |
| BPF + NET_ADMIN、默认 SELinux label、seccomp unconfined | 仍 EACCES |
| BPF + NET_ADMIN、label disabled、默认 seccomp | bytecode 加载、双向转发与分阶段测试通过 |
| BPF + NET_ADMIN、label disabled、seccomp unconfined | 同样通过 |

这里是容器隔离下的本地 socket 机制测试，客户端、转发 socket 和接收端都在
同一个测试进程中；不是 Kubernetes/CNI 测试，也不是完整 sidecar 部署。
未使用 `--privileged`，未添加 SYS_ADMIN，未修改宿主 sysctl 或全局 SELinux 策略。
`label=disable` 仅用于这些短生命周期实验容器；实际部署需匹配的策略或特权加载组件。
本机对比没有证明必须放开 seccomp。

成功的内核路径逐字节验证两方向各 1 MiB，加后续 17 B，共 2,097,169 B；
两次接收前延迟 100 ms。转发端 body 用户态读写计数为 0，测试端点仍在用户态。
这是避免 body 经过转发端用户空间的证据，不代表内核零复制或整个进程不进用户态。
半关闭时由用户态观察 EOF、调用 shutdown，四侧 EOF 验证通过。

### header 与 body 分阶段处理

受控 HTTP header fixture 在用户态把 `Host: old` 改为 `Host: rewritten`，
确认原始 header 54 B 及改写后的完整 header，再启用内核 body 路径。
header 长度变化不强制后续所有 body 都经过用户态。
这不是完整 HTTP parser 测试；读取使用 fixture 的已知 header 边界。

限定 body 模板每方向设置 1 MiB 预算，以 4 KiB 逻辑帧处理。
最后一次 send 同时包含末尾 4 KiB body 和后续 17 B，body 完整到达另一端，
17 B 通过 SK_PASS 回到本侧用户态，并确认未转发到另一端。
预算耗尽后以 1 B 帧向用户态传递：这是边界正确性的原型，不能据此推断性能。
未实现下一请求解析、预算重置、完整 HTTP keep-alive、chunked 或 HTTP/2。

### 部分挂载失败与缓存数据

只挂入前端 socket 后注入 EIO，auto 明确删除已插入的 map 项、释放 BPF FD，
**保留原来的 TCP 连接**并走 copy；全部数据与改写 header 保持正确。
required 对这个加载失败返回 1。未把已经发出的 payload 重放给用户态。

若 header 与 4 KiB body 在同一次发送中到达，用户态读完 header 后直接挂入
sockmap 的早期原型发生停传。[失败记录](prequeued-before-fix.log) 保留原始结果。
最终原型在插入 socket 前检查 FIONREAD：已有数据时选择 copy，相关场景通过。
**检查队列为空只是快照；并发到达与挂载之间仍存在窗口，未证明原子切换。**
因此当前实现只用于受控实验，不能作为生产 L7 offload 的安全条件。

重复测试还否定了“直接按 skb.len 扣 body 预算”的实现：存储长度可以包含
当前逻辑帧之外的字节，body 与后续数据共用 skb 时会停传。
[失败记录](variable-frame-failure.log) 保存了这个发现；最终采用固定逻辑帧长度计数。
内核转发实际使用 strparser 的 message offset/full_len，不能将它们与 skb.len 等同。
参见 [上游 skmsg.c](https://github.com/torvalds/linux/blob/master/net/core/skmsg.c)。

### kTLS 兼容性

只测试安装 API，使用隔离的新 socket 与合成 TLS 1.2 AES-GCM 密钥；
没有 BoringSSL 握手、TLS 数据、TLS_RX 或 KeyUpdate 测试。

- 单独配置 TLS_TX 成功。
- 先 sockmap 再配置 TLS_TX：当前内核接受。
- 先配置 TLS_TX 再插入 sockmap：EINVAL。

这种顺序差异不能当作部署保证。[上游明确拒绝 TLS 与 sockmap 的组合](https://github.com/torvalds/linux/commit/460e648)，应把它们作为不同能力和路径处理。

## 对编译器接入的约束

未来 `.rut` 编译产物可包含用户态实现、BPF bytecode、版本化能力清单和重定位。
编译器证明整条路径的语义适用性；加载器验证实际 program/map/helper、权限、
verifier 与挂载；运行时再判断该次请求、缓存字节与连接状态是否符合切换条件。
不能仅按内核版本、路由关键词或连接第一次请求决定是否下沉。

下一步接入前必须解决原子接管与退回、并发到达、关闭/reset、热更新及旧 map
回收。优先限定 Content-Length 的 HTTP/1 路径，保留 regex/动态 header 用户态处理；
chunked、完整缓冲、重试与 HTTP/2 的语义证明分别处理。
这轮不新增 DSL keyword，不把尚未实现的 compiler flag 写成现有能力。

## 复现与检查

```bash
cmake -S . -B build -DRUT_BUILD_EBPF_PROBE=ON
cmake --build build --target bench_sockmap_probe check_sockmap_probe
ctest --test-dir build -R '^test_sockmap_probe$' --output-on-failure

# prefix 的文件必须尚不存在；发射不需要 BPF 权限。
build/bench/bench_sockmap_probe emit /path/to/new/tunnel
build/bench/bench_sockmap_probe auto --bytecode /path/to/new/tunnel
build/bench/bench_sockmap_probe required --bytecode /path/to/new/tunnel \
  --header-rewrite --bounded-body
```

容器矩阵需先准备实验目录：`probe`（构建的探针）、与其匹配的已复制 glibc
`loader`/`libc.so.6`、发射的 `tunnel.*.bpf` 四个文件。文件需可被容器 UID 读取；
只给这些实验副本设置容器可读的 SELinux label，不改系统库。
控制脚本不拉镜像、不安装软件、不修改这些文件。

```bash
python3 scripts/ebpf_capability_probe.py --stage /path/to/staged-artifacts \
  --out /path/to/new-results --repeats 3
```

验证：探针构建、5 个黑盒测试、相关两个 CTest、ON/OFF 目标存在性、受影响
C++ 的 clang-format、Python py_compile、git diff --check 通过。
按仓库 clang-tidy 配置检查，bugprone/performance/clang-analyzer/readability
错误门通过；剩余 misc 风格/include-cleaner 警告不计作无警告。
未跑完整测试集或完整项目 tidy。未接入生产后端，也未进行 eBPF 吞吐测试。

[结果 JSON](results.json)、[汇总](summary.json)、[环境与哈希](manifest.json)
与日志保存在本目录；[证据归档](evidence.tar.gz) 含探针 ELF 和四份 bytecode。
