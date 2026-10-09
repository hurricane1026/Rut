# 四核 origin 对单核前端：Rut / nginx

单个 origin 实例、4 worker 使用四个物理核 CPU3,4,8,9；前端1 worker固定CPU2。96条1MiB与32条4KiB长连接，客户端分别CPU7/5。端口8604/8704，origin multi_accept on。所有前端串行，3轮、每轮预热3秒测量15秒。nginx1.29.7固定镜像，proxy_buffering off，proxy_buffer_size 1024k（沿用之前的大响应对照设置）。Rut二进制使用相同请求阶段采样。

| 前端 | 1MiB RPS | 1MiB p99 ms | 4KiB RPS | 4KiB p99 ms | 总载荷 GiB/s |
|---|---:|---:|---:|---:|---:|
| uring | 3075 | 33.907 | 43990 | 1.359 | 3.169 |
| baseline-uring | 2478 | 45.249 | 39182 | 1.146 | 2.570 |
| nginx | 3888 | 102.617 | 1339 | 25.579 | 3.802 |

uring 为128KiB relay，baseline-uring为原始64KiB八段方案。所有9次有效测量无客户端错误。Rut先测、nginx后测，未交错三种前端，因此仍可能有时间漂移。

闭环固定连接数并不固定实际请求比例。nginx完成更多大响应、Rut完成更多小响应，不能仅从此表断言相同请求比例下的容量胜负，也不是纯1MiB容量测试。下一步若评估相同工作量，需固定到达率/请求比例的对照。
