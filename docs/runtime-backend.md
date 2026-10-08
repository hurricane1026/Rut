# 选择运行时 I/O 后端

Linux 上通过 `rut` 的 `--backend` 参数选择后端：

```bash
rut program.rut --backend epoll --shards 1
rut program.rut --backend io_uring --shards 1
rut program.rut --backend auto --shards 1
```

默认是 `auto`：探测 io_uring，不可用时选择 epoll；TLS 的 io_uring 初始化失败时保留原有 epoll 回退。
显式 `epoll` 跳过 io_uring 探测。显式 `io_uring` 在不可用或初始化失败时退出，不静默切换后端。
启动日志输出实际使用的后端。macOS 仅接受 `auto`，继续使用 kqueue。

后端选择属于运行时启动配置，不改变 DSL 或编译产物；内部 `rut-compile` 辅助程序不需要此参数。
性能比较应使用同一二进制、相同程序和负载，并检查响应、错误和实际后端日志。
