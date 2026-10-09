# 纯 1MiB 长连接：四核 origin 对单核前端

origin 单实例4 worker、4物理核CPU3,4,8,9；前端单worker CPU2；wrk CPU5,7、128条长连接。预热3秒、测量15秒，3轮按三种前端轮换顺序串行运行。端口8604/8704。origin multi_accept on、文件响应、sendfile默认off；nginx1.29.7固定镜像，proxy_buffering off、proxy_buffer_size 1024k。Rut io_uring 两种方案均为同一请求阶段采样版本；本负载无4KiB样本。

| 方案 | RPS 中位数 | 载荷 GiB/s | p50 ms | p99 ms 中位数 | 各轮 p99 ms |
|---|---:|---:|---:|---:|---|
| uring | 5527 | 5.398 | 23.001 | 26.197 | 25.755, 26.697, 26.197 |
| baseline-uring | 4267 | 4.167 | 29.612 | 34.569 | 33.867, 34.985, 34.569 |
| nginx | 3969 | 3.876 | 32.066 | 264.649 | 293.366, 264.649, 33.992 |

uring=128KiB relay；baseline-uring=原始64KiB八段方案。所有9次测量valid且无客户端错误。nginx两次p99偏高、一次约34ms，波动明显，尚未定位此配置下长尾原因，不能推广到所有nginx配置。结论仅适用于本机、此纯1MiB长连接负载和配置，未测试短连接、TLS或多核前端。
