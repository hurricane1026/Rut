# 保留的 proxy 优化检查点

旧 io_uring 二进制来自已验收的 bin-adaptive-cache-close，sha256 固定为 0e8b7a2aac39bb80cdb44b8d5840a1ef62cc47b5be53bb977a7d105b4a061e7d。
old-iouring 中 compiler helper 一同保存；new-epoll 为当前工作区二进制及其 helper 的冻结副本，wrapper 显式 --backend epoll。

旧源码独立保存于 /home/hurricane/private/code/Rut-proxy-flow-checkpoint，分支 experiment/proxy-flow-checkpoint-20261007，以 f1678e9a 加原始验收 prototype.patch 构成。
该检查点包含试验开关和计数器，未把失败的 SEND_ZC 或正文对齐方案启用为默认。
候选环境见 old-candidate-env.json；SEND_ZC/ZC_PUSH/BODY_ALIGNMENT 必须不设置（设置成0也会开启）。

原始验收是 converter-bounded+origin reuse；epoll不支持该显式deadline能力，跨版本对照使用 native-streaming，不能把两个profile的数字混为同一收益。
新旧源码、二进制与原始数据均保留；没有覆盖、合并或推送工作区代码。

持久二进制清单：/home/hurricane/private/code/rut-performance-checkpoints/proxy-flow-20261007/binaries.json
