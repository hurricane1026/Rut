# rut-node:静态、零依赖的边缘分发

> 状态:设计完成;去风险**部分验证**(2026-06-22 跑过,但当时 harness 链的是系统
> OpenSSL,见 §5 复现修正)。musl-static / 零 `.so` / 零 libstdc++ 已验证;**BoringSSL
> 链接 + 体积仍待在修正后的 harness 上复跑确认**。实现未开始。

## 1. 动机

目标:让 rut 的运行节点像 Go / Zig 二进制一样——**拷过去就能跑,不依赖任何动态库,
最好连 glibc 都不要**。

核心痛点是 **glibc 版本地狱**:在新 glibc 上编的二进制拷到老机器会
`version 'GLIBC_2.34' not found`,逼得构建环境的 glibc 必须 ≤ 所有目标机器里最老的那台。
这就是"管理每台服务器依赖"的本质。

**完全静态链接(musl)把 libc 烤进二进制**,运行时不再向系统要任何符号,glibc 这根轴
彻底消失,剩下的只有 CPU arch。于是分发管理面从"每台机器的 glibc 版本"塌缩成"一个小而
固定的 arch 构建矩阵"。

## 2. 架构:rut-master / rut-node 切分

rut 有 **compile** 和 **load** 两条路。把它们拆成两个分布式角色:

| | rut-master(管理节点) | rut-node(边缘节点) |
|---|---|---|
| 数量 | 少,环境自控 | 多,遍布边缘,要 copy-and-run |
| LLVM | ✅ 编译 `.rut` → native | ❌ 无 |
| 职责 | 编译 + 序列化产物 + 推送(code/endpoint/cert) | 加载并运行预编译产物 |
| libc | glibc 无所谓 | **musl-static,零 `.so`** |

**这是构建配置维度的切分,不是代码分叉。** 一份源码产出三个构建画像:

| 二进制 | 版本 | LLVM | 正则 | 加载 | libc |
|---|---|---|---|---|---|
| `rut`(单体) | 免费 | ✅ | Vectorscan 全量 | 进程内 compile→run | 动态 glibc |
| `rut-master` | 收费 | ✅ | 编 + 序列化 DB | compile + emit 产物 | glibc |
| `rut-node` | 收费 | ❌ | `hs_runtime` 反序列化 | 自研加载器,无 dlopen | musl-static |

现有代码库已具备接缝:`rut_jit` 是唯一链 LLVM 的库,`rut_runtime` 保持 LLVM-free
(`src/CMakeLists.txt:310`),`RUT_ENABLE_JIT` 开关已存在(`CMakeLists.txt:28`)。
新增组件(产物 emit、自研加载器、`hs_runtime` 链接、musl 构建)都是 build-time 可组合的
附加能力。**收费门禁正交**——是商业 flag,不影响技术结构。

## 3. rut-node 硬约束与推论

约束:**完全静态、`readelf -d` 零 `NEEDED`、copy-and-run、只管 CPU arch**。
由此锁定的设计:

### 3.1 libc 必须 musl-static,不能 glibc-static

glibc 的 **NSS** 是隐蔽杀手:`getaddrinfo`/`gethostbyname` 底层走 NSS,**即使 `-static`
也会在运行时 `dlopen` 出 `libnss_*.so`**,破坏零 `.so`。musl 没有 NSS,解析器内建、完全
自包含。这是"真静态分发用 musl 不用 glibc-static"的根本原因。

### 3.2 加载 handler:不能 dlopen → 自研最小重定位加载器

musl 静态二进制里 **`dlopen` 永远失败**,所以 DESIGN §16 原计划的 "sidecar dlopen .so"
不可用。替代方案是一个**极小的 `.o` 重定位加载器**:handler 产物的未定义符号是固定的一小撮
(那 22 个 `rut_helper_*`,见 `jit_engine.cc:46-69`),所以加载器只干四件事:

1. `mmap` 产物的代码/数据段
2. 套用重定位(`R_X86_64_64` / `PC32` / `PLT32` / `GOTPCREL` 等)
3. 把固定的 `rut_helper_*` ABI 表地址填进去(查静态表,非符号名搜索)
4. `mprotect(PROT_EXEC)`,定位入口,交给 RCU

这是 LLVM RuntimeDyld / musl `ld.so` 的一个**符号集固定**的子集,几百行而非几千行。
**复杂度应压给 master**:让 master(带 LLVM、少数、自控)把 handler 预链接成自包含 PIC
产物,换 node 加载器尽可能小、不可能出错。

> 当前代码**还没有 load-only 路径**——`jit_engine.cc:397` 只有进程内 IR 编译。
> 把"编译"和"加载"劈成两半是净新增工作。

### 3.3 正则:Vectorscan serialize / deserialize(不是 DFA)

Hyperscan / Vectorscan 本就是 "中心编译 → 序列化 → 下发 → 节点反序列化扫描" 模型,
与 master/node 一一对应:

- **master**:`hs_compile_multi` → `hs_serialize_database` 序列化进 handler 产物
- **node**:只链 `hs_runtime`(运行时库,无编译器)→ `hs_deserialize_database` → `hs_scan`

扫描调用本身已存在(`runtime_helpers.cc:529` 的 `hs_scan`/`hs_alloc_scratch`),但**它现在
编进 `rut_jit` target,而 `rut_jit` 链 LLVM + 完整 `hs`**(`src/CMakeLists.txt`)——不是
LLVM-free 的 `hs_runtime` 库。所以 node 侧不是"只换 DB 指针"就能复用:要做两件事——
(a) 把这段扫描代码**拆进一个 node-safe、只链 `hs_runtime`(无 LLVM、无完整 `hs`)的 target**;
(b) DB 从"烤进 IR 的进程内指针"(`jit_engine.cc:251-256`,跨机器无意义)改为
**序列化进产物 + node 反序列化按 handle 接上**。

注意:① **ISA 对齐**——`FAT_RUNTIME=OFF` 下扫描引擎单 ISA,master 编 DB 的目标 ISA 必须
≤ node 运行时基线;② **版本耦合**——序列化 DB 版本绑定,master/node 用同一 vendored
Vectorscan 天然满足。

单体 rut 仍用全量 Vectorscan,保留多模式 SIMD 能力。**放弃了自研 DFA 方案**(那需要写
编译器+执行器两套,而 Vectorscan 序列化几乎零新代码)。

### 3.4 TLS:BoringSSL

BoringSSL 在 musl-static 下能编能跑,比 OpenSSL 自包含得多(无 provider/ENGINE)。无代码改动。

### 3.5 HTTP/2:自写,不依赖 nghttp2

只实现所需子集,并入 rut runtime,又少一个第三方依赖。

## 4. 每-arch 分发

一个 native ELF 就是单 arch 的,**不可能一个二进制含所有 arch**——这正是 Go/Zig 的模型:
每 arch 出一份,分发时按目标机器挑(小而固定的构建矩阵,x86-64 + arm64 基本覆盖)。

两层 native 码都按 arch 处理:

| native 码 | 谁出 | per-arch 方式 |
|---|---|---|
| rut-node runtime 二进制 | 预构建 | 每 arch 一份 musl-static;**钉保守基线**(如 x86-64-v2)跑遍新老 CPU |
| handler 产物 | rut-master | LLVM 天生交叉编译器,按节点 arch emit;**可特化到该节点精确 CPU** |

→ 分发的 runtime 求"跑得到处都行",推送的 handler 求"为这台机器榨满性能",一保守一特化。

## 5. 去风险实测(Alpine musl,已验证)

复现脚本见 `scripts/musl_derisk/`。

### 5.1 musl-static 可行性

| 验证项 | 结论 |
|---|---|
| musl 静态编 C | ✅ 完美,`readelf -d` 无 `.dynamic`,零 NEEDED |
| vendored vectorscan `hs_runtime`(FAT_RUNTIME=OFF,static)musl 编译 | ✅ 成功,`libhs_runtime.a` 1.73MB |
| TLS(**vendored BoringSSL** static,`third_party/boringssl`)musl 静态链 | ⏳ **待复跑确认**(原始实测链的是系统 OpenSSL;harness 已改为 vendored BoringSSL 但未在 musl 环境重跑) |
| 最终二进制 `readelf -d` | **零 NEEDED**;`ldd` = "Not a valid dynamic program" |
| **libstdc++ / 异常符号** | **0** —— rut 本就 no-STL,vectorscan runtime 那 13 个 `.cpp` 只用模板+SIMD intrinsics,不碰 STL/异常 |

**关键收获:rut-node 整个二进制可不背任何 C++ 运行时,只靠 musl libc。**

> **复现修正(2026-06-23):** 早期 harness 链的是 Alpine `openssl-libs-static`(系统 OpenSSL),
> 而不是 vendored BoringSSL —— 与本节"BoringSSL"结论及下面的体积数不符,也违反"不引系统
> OpenSSL"的项目约束。`scripts/musl_derisk/` 已改为**现场编 `third_party/boringssl` 并链其
> `.a`**、头走 vendored `-I`、各断言 fail-hard、`nm` 在 strip 前。**BoringSSL 的链通与体积数
> 应在修正后的 harness 上重跑确认**(本次修正未在 musl 环境复跑)。

### 5.2 构建工具链

**必须用 Alpine 或 musl-cross-make,不能用 Fedora 的 `musl-gcc`**——后者是 C-only wrapper,
不带 C++ 头/库,编不了 vectorscan 的 C++。Alpine 原生 `g++` 是完整 musl C++ 工具链,一遍过。

### 5.3 体积(`-O2` + gc-sections + strip,实测)

| 组件 | 体积 | 来源 |
|---|---|---|
| musl 地板 | **13 KB** | 实测 |
| 正则(vectorscan `hs_runtime`) | **~1.15 MB** | 实测 |
| TLS(**BoringSSL**) | **~2.5 MB**(⏳ 待复跑) | OpenSSL 同测法 4.25MB(gc 对其 provider 体系几乎无效,故选 BoringSSL)。BoringSSL 的 2.5MB 需在修正后的 harness(vendored BoringSSL)上复测确认——原始实测链的是系统 OpenSSL。 |
| rut runtime + 自写 h2 | ~0.3–0.6 MB | 估算(node 构建未成型) |

档位:

| 档 | 体积 |
|---|---|
| 极简(HTTP/1,无 TLS/正则) | **~0.3–0.5 MB** |
| + 正则 | ~1.6 MB |
| + TLS | ~3 MB |
| 全功能(HTTP/1+2 + TLS + 正则) | **~4 MB** |

**体积 = 功能预算,与性能正交**:gc-sections / strip / LTO 都不降速,无需 `-Os`。最大杠杆是
TLS(~2.5MB)和正则(~1.15MB),都是可后加的 feature-gate,不改架构。

### 5.4 k8s sidecar

静态 musl → **`FROM scratch`**(空基础镜像)。实证:**镜像大小 == 二进制大小,0 字节开销**
(10KB 二进制 → 10.2KB 镜像)。glibc 动态二进制做不到(需 `ld.so`+`libc.so`+NSS,得垫
distro/distroless 基础层)。

→ 纯路由/代理的 rut-node sidecar(无 TLS、无正则)≈ **0.3–0.5MB scratch 镜像**,
对比 Envoy ~50–150MB,**小 100–300 倍**。附带:无 shell、无包管理器、无基础 OS →
零 base-OS CVE;拉取/启动近乎瞬时;多 arch 走 OCI manifest list。

## 6. 剩余工程

| # | 工作 | 规模 | 耦合 |
|---|---|---|---|
| ① | 产物格式 + 无 LLVM 加载器 | 净新增(最大) | 产物格式要同时装 handler PIC 码 + 序列化的 Vectorscan DB |
| ② | 正则改 serialize/deserialize + 链 `hs_runtime` | 小 | 与 ① 耦合 |
| ③ | BoringSSL + `hs_runtime` 的 musl-static 构建 | ⏳ **待复跑**(见 §5.1) | 独立 |

①② 必须一起设计(产物格式预留 DB 位置)。③ 的 musl-static + zero-`.so` 已验证,但
**BoringSSL 部分**原始实测链的是系统 OpenSSL,改用 vendored BoringSSL 的 harness 尚未在 musl 重跑。

## 7. 复现

```bash
# 见 scripts/musl_derisk/
#   derisk.c    —— 同时触达 vectorscan runtime + TLS 的 musl-static 链接验证
#   tls_only.c  —— TLS 单功能体积测量
# 在 Alpine 容器中编 vendored vectorscan hs_runtime + BoringSSL,静态链接,
# readelf -d 验收零 NEEDED,nm 验 libstdc++ 符号为 0。
```
