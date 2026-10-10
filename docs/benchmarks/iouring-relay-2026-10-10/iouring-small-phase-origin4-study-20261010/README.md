# 4KiB 与 1MiB 混合负载：上游首字节阶段研究

单个 Rut worker 固定 CPU2，96 个 1MiB 长连接客户端和 32 个 4KiB 长连接客户端分别固定 CPU7、CPU5。15 秒测量、3 秒预热，前端串行运行。两个 binary 均包含相同的随机约 1/64 请求阶段采样，未增加 Connection 字段。

uring = 128KiB relay，baseline-uring = 原始 64KiB 八段方案。采样仅选择解析所得 Content-Length=4096；上游首字节区间包含提交、网络、origin 和完成事件调度，不能等同于 origin 自身处理时间。

| 方案 | 大响应 RPS | 大响应 p99 ms | 小响应 RPS | 小响应 p99 ms |
|---|---:|---:|---:|---:|
| baseline-uring | 2431 | 46.624 | 38295 | 1.210 |
| uring | 2917 | 36.502 | 43338 | 1.219 |

所有 6 次测量 valid 且无客户端错误。闭环客户端的实际请求比例随完成速度改变，因此不能把混合负载的大响应 RPS 直接当作纯大响应容量。

配置和原始日志见子目录 environment.json、origin 配置、server.log 与顶层运行日志。初次无采样的尝试如存在已单独保留并排除。四 worker 实验是单一 origin 实例使用四个核，不是四个独立实例。不同目录端口不同，结论待同端口对照确认。
