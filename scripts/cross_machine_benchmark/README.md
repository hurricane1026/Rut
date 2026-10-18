# 万兆跨机器 Rut / nginx 对照测试

拓扑：`客户端 C → 代理 P（Rut 或 nginx）→ 上游 O`。推荐三台独立 Linux
机器、同一万兆交换机；使用万兆网卡的 IPv4 地址。两种代理在 **同一台 P、同一个
端口、同一组 CPU** 上顺序运行。不要同时启动。这里测 HTTP/1.1 明文 streaming
proxy，不能代表 TLS、小包、真实业务或所有部署环境。

依赖：三台机器都有 Python 3、iproute2；服务端有 taskset。O 和 P 使用同版本 nginx；
P 有待测 `rut` 和 **同一次构建生成的同目录 `rut-compile`**；C 有 wrk（支持
`--latency`）。使用已有构建，不自动安装软件、不修改网卡/XDP/sysctl、不自动关闭服务。
将本目录复制到三台机器。以下在本目录执行。所有输出目录必须是新目录。

## 0. 记录网络和构建条件

在三台机器记录 `ip -details link`、`ip route`、`uname -a`；记录万兆网卡的
`ethtool 网卡名`、`ethtool -k 网卡名` 和 `nginx -V`。脚本自动保存基本网络信息及
实际执行的 binary SHA256；将上述补充信息也放进实验归档。确认路由经过万兆网卡，
不是 WireGuard、其他 VPN、loopback 或 Docker NAT。**不要为某个引擎单独改变环境。**

可先用已有 iperf3 测 C→P 和 O→P 的单向/反向带宽；不要与 HTTP 测试同时运行。
MTU、offload、CPU governor、XDP、网卡队列配置在整个对照期间保持一致。

`RUT_STUDY_HTTP_ASYNC_SPLICE=on` 会由 serve 显式设置，并要求 `--backend io_uring`。
使用包含该开关实现的性能验证版本；环境变量本身不能证明任意旧版本真的支持 splice。
保留服务启动日志并核对后端。脚本不会关闭 splice 或自动回退到 epoll。

## 1. 上游 O

下面假设 O 为 `192.0.2.30`，P 为 `192.0.2.20`；替换为实际万兆地址。
O 用 4 个 worker，避免单个上游 CPU 提前成为瓶颈；按机器核数修改 CPU 列表。

```bash
python3 bench.py prepare --output /tmp/origin-1m --port 9087 --workers 4 --body-size 1048576
python3 bench.py serve --engine origin --config /tmp/origin-1m --binary /absolute/path/nginx --cpus 2-5 --endpoint 192.0.2.30:9087
```

`serve` writes `/tmp/origin-1m/server-manifest.json`; copy this one live origin
manifest to C and use it for every proxy repetition.

保持前台运行。响应是确定性二进制文件，URL 为 `/proxy`，允许上游连接复用。
仅在受信任测试网络开放 P 的 8087 与 O 的 9087 端口；服务监听所有 IPv4 地址。

## 2. 代理 P

```bash
scp O:/tmp/origin-1m/server-manifest.json P:/tmp/origin-1m-server-manifest.json
python3 bench.py prepare --output /tmp/proxy-1m --origin 192.0.2.30:9087 --port 8087 --workers 1 --body-size 1048576
python3 bench.py serve --engine rut --config /tmp/proxy-1m --binary /absolute/path/rut --cpus 2 --origin-manifest /tmp/origin-1m-server-manifest.json
```

On C, copy the manifest produced on P before starting the client, and repeat this
after every proxy restart:

```bash
scp P:/tmp/origin-1m-server-manifest.json /tmp/origin-1m-server-manifest.json
scp P:/tmp/proxy-1m/server-manifest.json /tmp/proxy-1m-server-manifest.json
```

nginx 对照：先在代理终端 Ctrl-C 停止 Rut，确认端口释放，然后运行：

```bash
python3 bench.py serve --engine nginx --config /tmp/proxy-1m --binary /absolute/path/nginx --cpus 2 --origin-manifest /tmp/origin-1m-server-manifest.json
```

两种代理都使用上游 keepalive；nginx 关闭 proxy buffering。上游原文件和代理配置
均保存在生成目录。编译/启动不计入客户端计时。首次执行前检查打开文件数限制满足
并发需求，例如 `ulimit -n`。serve 替换为前台服务进程，Ctrl-C 不会杀其他服务。

## 3. 客户端 C

先等待代理启动，再执行一轮：

```bash
python3 bench.py client --host 192.0.2.20 --engine rut --rep 1 --cpus 2-5 --threads 4 --connections 128 --body-size 1048576 --warmup 5 --duration 30 --wrk /absolute/path/wrk --server-manifest /tmp/proxy-1m-server-manifest.json --origin-manifest /tmp/origin-1m-server-manifest.json --output results/1m/rut-1
```

每次换代理后执行同样命令，只改 `--engine`、`--rep` 和 `--output`。始终使用同一
origin manifest；重启或改变 O 会使整组配对结果失效。
**顺序：Rut 1 → nginx 1 → nginx 2 → Rut 2 → Rut 3 → nginx 3。**
每个引擎实例只测一轮，下一轮重启服务，即便引擎没变也重启。
客户端 `--engine` 是人工标记，务必与 P 当前运行的进程对应；`--server-manifest` 必须来自当前
服务进程，脚本会把服务端 CPU、worker 数作为配对坐标，并保留配置、binary 和 run identity
供审计；它不会远程切换服务器。
客户端命令通过 `taskset -c <cpus>` 固定 wrk 的 CPU 集合；代理服务命令也使用同一选项，
因此比较坐标会记录并校验规范化后的客户端 CPU 集合。
保存每轮服务端日志（启动命令可用 shell 重定向），不能依赖 HTTP Server 头识别 Rut。

脚本先用同一连接连续校验三次状态码、Content-Length、完整响应体和 keepalive，
然后预热、测量，再校验一次。保存 warmup/measurement 原始输出、参数和结果。
预热或测量出现连接/read/write/timeout/status 错误则本轮无效，不可删除失败轮次后
只报告成功结果。wrk 不逐字节校验全部压测响应；完整性校验是压测前后独立执行的。

```bash
python3 summarize.py results > summary.json
```

汇总要求相同坐标下两种引擎至少三轮配对，输出 instrumented RPS 样本、RPS 中位数
和 P99 中位数，并标记 `inconclusive-lua-body-callback`。汇总不输出代理吞吐或 Rut
相对收益结论。不要把不同构建、网络设置的实验放进同一 results 目录。
当前脚本的 wrk Lua `response()` 回调会接收完整响应正文；因此结果中的 RPS 是带
客户端正文回调的端到端测量，汇总脚本将其标为 throughput-inconclusive，不得解释为
代理容量或 Rut 性能收益。只有另有独立客户端余量证据并更新此契约后，才可作代理吞吐结论。
RSS/CPU 没有远程自动采集：可在 P 用已有 pidstat/监控工具记录**整个服务进程树**，
nginx 要包含 master/worker；RSS 不包含内核 socket/pipe 内存。不要把客户端 CPU
当作代理 CPU。记录 C、P、O 的 CPU 与 NIC 利用率，识别客户端/上游/链路瓶颈。

## 万兆测试矩阵与解释

至少测试响应大小 `1024、4096、16384、65536、262144、1048576` 字节，
并发 `32、128、512`，先单 worker，再测多 worker（两边相同）。切换大小时重新生成
O/P 的目录、重启服务，并同步修改客户端 `--body-size`。先做 1 秒 quick smoke
（`--duration 1 --warmup 1`），正式结论使用上面的 30 秒 × 3 轮。

不要把这些 RPS 换算为有效载荷吞吐，也不要从结果推导两个代理的相对性能。

三机配置保持相同，改变 XDP 等设置必须作为新的实验组完整重跑。二机测试若把
客户端和上游放一起，要明确标注共享 CPU/NIC 干扰，不能与三机结果混合。
