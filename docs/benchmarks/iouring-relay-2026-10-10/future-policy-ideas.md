# Recorded runtime performance directions

- Future global CLI preference for lower latency versus higher throughput; not implemented or selected yet.
- Collect actual response size, frequency and latency distributions by route template/URL pattern at runtime. This is observed telemetry, not an assumption about a not-yet-seen response.
- Bind explicit performance policies to route configuration; reuse current route-policy infrastructure and avoid inventing syntax. No language feature is being added in these experiments.
- Prefer shared route-level policy and shard-local route counters over copying policy/statistics into every connection. Reuse existing route/request identity where lifetime permits. A keepalive connection can serve different routes; in-flight response policy lifetime must survive RCU replacement and transition safely at request boundaries.
- Preserve a shard-wide fairness/resource limit across route-specific policies, so throughput-oriented routes do not monopolize other work.

User requested these ideas be recorded while root-cause/performance testing continues. No URL prediction, configuration switch or per-connection policy implementation is included in the current candidate. No SEND_ZC, push or merge.

## 上游共享资源与策略（2026-10-10，待验证）

4KiB 混合负载的请求阶段采样提示，128KiB relay 的小请求延迟主要集中在上游首字节区间；该区间包含提交、网络、origin 和 CQ 调度，不能直接当作 origin 服务耗时。同一 origin 增加到四核四 worker，以及两核保持不变但关闭 multi_accept，都曾使小请求 p99 回到约 1.22ms。需同端口 A/B 和 worker CPU/连接观测确认。策略应同时考虑请求频率、SLO、上游资源和连接池共享；更多独立 origin 是可测试方向，当前尚未证明必需。
