# Rut 与 nginx 的响应缓冲实现对比

## 范围

检查本次 pinned Docker 镜像，`nginx -v` 返回 **nginx/1.29.7**。
nginx 源码采用官方 `release-1.29.7` 标签；未逐字节验证发行包是否存在下游补丁。
Rut 采用 #726 最终版本 `0b8fdcab9290d6b6a2093b775087efacd17c59bd`。
范围为普通 HTTP、Content-Length、开启代理响应缓冲、无缓存的路径。
不把结论外推至 TLS、压缩、缓存或所有 nginx 模块。

## 实现差异

| 项目 | nginx 1.29.7 | Rut 当前实现 |
|---|---|---|
| 分配与归属 | event pipe 使用请求池 `r->pool`；按需分配至配置数量上限 | shard 共享 SlicePool；正文链按需借用节点 |
| 数据块大小 | 本次 1 MiB 配置为 8 × 16 KiB，另有 16 KiB 首段缓冲 | 普通节点 16 KiB；bulk 节点 256 KiB，元数据占用部分空间 |
| 首次分配 | 描述符清零；正文经 `ngx_palloc` 分配，不要求正文全零 | 新匿名映射由 OS 提供零页，缓存节点由归还路径保证全零 |
| 请求内复用 | 发送完成后放回 free_raw_bufs，只重置 pos/last 和 shadow | 节点耗尽后归还共享池，再按需借用节点 |
| 归还时清零 | 普通正文复用路径不清零 payload；请求池释放也无统一正文擦除 | bulk 按 header + 实际写入长度清零；普通 slice 清满 16 KiB |
| 上游读取 | recv_chain → readv，可一次填入多个可用节点 | Bounded 正文直接 recv 到一个 tail 节点，收到完成事件后推进 |
| 下游发送 | memory chain 转为 iovec，经 writev 聚合多个 buffer | 当前正文链每次发送一个连续 front 区间，io_uring SEND 完成后继续 |
| 反压与内存 | 配置的节点数量、busy size 及 event pipe 调度；必要时可写临时文件 | 512 KiB 未释放正文窗口；达到阈值暂停接收，半窗口恢复，存在单次 recv 粒度的越界量 |
| 发布粒度 | event pipe 与所配 buffer 大小、可写状态共同决定 | 4 KiB 发布边界；小于 16 KiB 的释放可等待 200 us 合并，并非每 4 KiB 必发一次 |

128 KiB 的 nginx 正文缓冲容量、32 KiB busy 上限和 Rut 的 256 KiB
节点大小/512 KiB 窗口不是同一维度。busy 是现有缓冲中可用于发送的一部分，
不能再加到总容量上。nginx 的小块可通过向量 I/O 合并，不等于每个小块一次 syscall。
代码存在临时文件路径，不代表本次性能测试实际写了临时文件；本轮未测落盘次数。

## 关键源码证据

nginx：

- [ngx_create_temp_buf](https://github.com/nginx/nginx/blob/release-1.29.7/src/core/ngx_buf.c)：
  描述符由 calloc_buf 创建，正文由 palloc 创建；随后设置 pos/last/end。
- [ngx_palloc / ngx_destroy_pool](https://github.com/nginx/nginx/blob/release-1.29.7/src/core/ngx_palloc.c)：
  普通分配不清零；请求池释放调用 free，不先清空正文。
- [ngx_alloc](https://github.com/nginx/nginx/blob/release-1.29.7/src/os/unix/ngx_alloc.c)：
  使用 malloc；清零只在不同的 calloc 包装中显式发生。
- [ngx_event_pipe](https://github.com/nginx/nginx/blob/release-1.29.7/src/event/ngx_event_pipe.c)：
  优先取 free_raw_bufs；copy input filter 复制 buffer 描述符并建立 shadow，
  不复制整段正文；add_free_buf 重置游标后重新挂入可用链。
- [ngx_http_upstream](https://github.com/nginx/nginx/blob/release-1.29.7/src/http/ngx_http_upstream.c)：
  event pipe 的 pool 设置为请求池，bufs 与 busy_size 来自代理配置。
- [readv chain](https://github.com/nginx/nginx/blob/release-1.29.7/src/os/unix/ngx_readv_chain.c)、
  [writev chain](https://github.com/nginx/nginx/blob/release-1.29.7/src/os/unix/ngx_writev_chain.c)、
  [Linux send chain](https://github.com/nginx/nginx/blob/release-1.29.7/src/os/unix/ngx_linux_sendfile_chain.c)：
  构建 iovec；Linux send chain 的纯内存区间使用 writev。

Rut：

- `include/rut/runtime/slice_pool.h`: alloc_bulk、free、free_written、free_bulk。
- `include/rut/runtime/response_body_chain.h`: reserve_tail、consume、release_node。
- `include/rut/runtime/iouring_event_loop.h`: arm_response_read_direct_body_recv、try_advance_bounded_release。
- `include/rut/runtime/response_read_deadline.h`: 发布边界、窗口、合并等待常量。
- `src/runtime/io_uring_backend.cc`: add_send 使用一个地址/长度的 IORING_OP_SEND。
- `tests/test_network.cc`: bulk_free_written_rezeroes_the_written_prefix、
  bulk_buffers_are_lazy_bounded_zeroed_and_address_routed 等用例明确检查清零保证。

## 对性能的解释

确定的差异是 **Rut 主动多做了一遍正文写零，nginx 的上述热路径没有这遍工作**。
块大小会影响缓存局部性和周转次数，但改变块大小通常不会消除总写零字节数。
之前 128 KiB 缩小块、分段提前清零都未获益，与这个解释相容；
不能仅凭它们断言全部性能差距都来自清零。

已有 perf 的 42%–46% 是用户态周期采样中 memset 的占比，不是总 CPU 占比，
更不是删掉清零后吞吐可以提高 42%–46% 的预测。内核收发、调度和其他热点仍存在。
nginx 依赖有效数据边界，仅发送 pos..last；这与 Rut 的空闲缓冲全零保证不同，
不能把 nginx 不清零直接称作数据泄漏，也不能因此直接删掉 Rut 的全局清零。

## 建议的下一步：同一响应内复用节点

比继续调大/调小节点更直接的实验，是给 ResponseBodyChain 保留一个有界的
已发送节点复用队列：仍归当前响应所有，发送及接收的异步使用者全部完成后，
重置有效区间用于接收同一响应的后续正文；真正归还共享池时再清零。
这样保持共享池“上一拥有者数据已清除”的保证，尝试减少同一块物理内存在一次
长响应中反复清零的次数。此方案尚未实现或测量。

实现必须满足：

1. 空闲但仍归当前响应所有的节点也计入内存预算，不能悄悄扩大窗口。
2. 清零范围记录本次持有期间的写入高水位；重置 len 后不能只清最后一次写入。
3. send 完成、direct recv pin、取消和连接退休全部结清后，才可复用/归还。
4. 只发布本轮已接收的有效长度；旧正文不能被新一轮长度或错误路径暴露。
5. 请求结束、超时、EOF、取消和 keepalive 下一请求都必须完整回收。
6. 覆盖慢上下游、短读取、部分发送、TLS、池耗尽与脏字节哨兵测试，再做安静环境 A/B。

对于 1 MiB 响应，节省量取决于实际同时存活的节点及能否成功复用，不能预先承诺。
更长的流式响应理论上有更多复用机会。另一个独立方向是正文链 gather send，
让小节点也能批量发送；它需要解决 iovec 与异步完成的所有权，不宜与清零实验混在一起。

本轮仅研究实现，未修改运行时源码。所查 nginx 源文件暂存于
`/tmp/rut-nginx-buffer-review`。
