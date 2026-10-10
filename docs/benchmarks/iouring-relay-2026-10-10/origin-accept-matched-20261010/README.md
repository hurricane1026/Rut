# 同端口 origin multi_accept 对照

固定 Rut 128KiB candidate（含相同请求阶段采样）、前端 CPU2、单个 origin 两 worker / CPU3,4、客户端 CPU5,7；前端8604、origin8704。96个1MiB连接与32个4KiB连接，15秒测量、3秒预热。三轮交替顺序 on/off、off/on、on/off，串行运行。

| multi_accept | 大响应 RPS | 小响应 RPS | 小响应 p99 ms 中位数 | 各轮小响应 p99 ms |
|---|---:|---:|---:|---|
| on | 4600 | 19447 | 3.636 | 5.086, 3.636, 2.779 |
| off | 3293 | 44213 | 1.229 | 3.538, 1.209, 1.229 |

六次有效测量均无客户端错误。off 提高小请求服务率，但仍有尾延迟波动；混合闭环负载请求比例改变，不能把大响应 RPS 直接解释为单独容量下降。

各 case 的 origin-worker-cpu.jsonl 保存 worker 用户态/内核态 CPU tick。第二轮 on 和第三轮 on/off 增加 fd 列表快照；这是总 fd 数，不是按请求类型的连接数，也不是 accept 事件累计数。CPU 观测没有证明一个 worker 始终闲置。

on-r2-failed-fd-links 保留因读取其他 UID 的 fd 符号链接被拒绝而中止的尝试，未进入测量结果；改为仅列 fd 编号后重跑成功。初始三次测量无 fd 快照。

前序四核实验是单个 origin 使用四 worker，尚未测量多独立 origin。当前结果支持将上游资源和接收策略作为实验变量，不能断言增加独立实例必需。
