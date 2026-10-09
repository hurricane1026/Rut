# nginx 缓冲配置扫描：纯 1MiB 长连接

固定 nginx 1.29.7 镜像、前端单worker CPU2、origin单实例4 worker CPU3,4,8,9（四个物理核）、wrk CPU5,7、128条长连接；端口8604/8704。origin multi_accept on、sendfile默认off。所有压测串行，无并行前端或构建。

初筛11组，每组预热3秒测量10秒，固定随机种子打乱顺序。off 的 proxy_buffer_size 为16/32/64/128/256/512/1024KiB；on 使用16KiB首部buffer与8×16/64/128/256KiB响应buffer，busy为2×响应buffer。统一禁用临时文件写入 proxy_max_temp_file_size 0；不开缓存。

初筛选择最高吞吐与最低p99两组，最终选到 off-1024k、off-512k。复测这两组及Rut128KiB，每组3轮、每轮预热3秒测量15秒，轮换顺序。每个 nginx case 保存启动时实际 effective-nginx.conf，扫描字段以 scan-config.json 为准，原始harness arguments里的native-nginx-buffering=off不是on case有效配置。

## 初筛（每组仅一次，供选候选）

| 配置 | RPS | p99 ms | RSS MiB |
|---|---:|---:|---:|
| off-16k | 1563 | 93.761 | 19.3 |
| off-32k | 2223 | 67.806 | 19.8 |
| off-64k | 2609 | 52.924 | 21.7 |
| off-128k | 3495 | 38.597 | 17.6 |
| off-256k | 3705 | 35.787 | 17.7 |
| off-512k | 3985 | 33.441 | 38.3 |
| off-1024k | 3998 | 388.797 | 18.0 |
| on-8x16k | 2335 | 62.684 | 25.1 |
| on-8x64k | 3380 | 39.104 | 26.9 |
| on-8x128k | 3004 | 374.955 | 43.5 |
| on-8x256k | 3698 | 49.094 | 47.4 |

## 复测（三轮中位数）

| 配置 | RPS | 载荷 GiB/s | p99 ms 中位数 | 三轮 p99 ms |
|---|---:|---:|---:|---|
| off-512k | 3963 | 3.870 | 33.379 | 33.084, 263.183, 33.379 |
| off-1024k | 4001 | 3.907 | 33.374 | 33.374, 238.490, 32.836 |
| rut-128k | 5543 | 5.413 | 26.280 | 26.359, 26.280, 25.442 |

20次测量均valid且客户端错误全为0，响应内容/长度与上游复用preflight均成功。扫描未找到超过此前1MiB读取缓冲的nginx吞吐配置；512KiB接近且实际占用内存更小（见各case RSS）。Rut相对复测吞吐最高的nginx约高 38.6%。

nginx两个候选均出现一次200ms以上p99，其余约33ms，前次264ms中位数不是稳定上限。此次复测p99中位数约33ms，Rut约26ms。尚未定位nginx间歇长尾原因。此次只扫描缓冲配置，不代表全部nginx性能参数已最优；初筛一轮有噪声和选优偏差，on配置未全部三轮复测。没有测短连接、TLS、多核前端或混合负载，也未改变Rut实现。

参考 nginx 官方代理模块文档：https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffering 。off时读取量受proxy_buffer_size限制，on时使用proxy_buffers；proxy_max_temp_file_size=0排除落盘影响。
