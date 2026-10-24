# Rutlang：设计文档

> 一个强类型 DSL 和高性能 L7 入口运行时。API 网关、WAF、反向代理、服务网格 sidecar、CDN 边缘节点：一门语言，多种编译目标。

## 状态与范围

这份文档目前同时承担三种角色：

- **规范性的语言 / 运行时说明**：描述 Rutlang 期望提供的契约
- **实现设计文档**：描述编译器、JIT / eBPF 代码生成、运行时和热重载路径应如何工作
- **路线图**：描述尚未完整实现、但计划支持的能力

这种混合写法有利于设计探索，但也很容易让人把“目标中的能力”误读成“今天已经 shipping 的行为”。除非某一节显式说明了当前实现状态，否则下面的语言与运行时章节都应理解为 **目标契约**，而不是“当前仓库已经完整实现”的声明。

### 阅读指南

- **偏规范 / 契约的章节**：语言语法、类型系统、路由语义、状态语义、编译期检查
- **偏实现设计的章节**：运行时架构、内存布局、I/O 后端设计、热重载内部机制
- **偏路线图的章节**：更高级的 TLS 能力、sidecar 集成、部分跨节点 / 分布式能力、可观测性扩展

当实现与设计出现偏差时，仓库内的真实优先级应为：

1. 覆盖当前行为的测试
2. 当前实际可达的运行时 / 编译器代码路径
3. 本文档中定义的目标行为

### 实现状态矩阵

这张表刻意保持粗粒度，它的目的是区分“已经设计好”与“今天已经能被稳定依赖”的能力。

| 领域 | 状态 | 说明 |
|------|------|------|
| 运行时事件循环、分片、socket 处理 | **已实现** | 仓库中已经有 epoll / io_uring 运行时核心 |
| HTTP 解析与代理运行时 | **已实现** | 已有面向生产路径的实现与测试 |
| RIR 数据模型 + builder + printer | **已实现** | RIR 真实存在，并且有测试覆盖 |
| LLVM ORC JIT 集成 | **已实现** | JIT 引擎和 codegen 路径已经存在 |
| 离线 manifest → RIR → JIT simulate 流程 | **已实现** | 当前“类似编译”的路径是刻意收窄过的 |
| `firewall` → eBPF / XDP 编译目标 | **已设计** | 语言设计明确要求该路径生成 eBPF bytecode，而不是用户态 handler |
| 完整 Rutlang lexer / parser / type checker | **部分完成 / 进行中** | token 面已经声明，但前端尚未闭环 |
| 路由冲突分析和完整诊断 | **已设计** | 文档里有说明，但当前还没有端到端全部落实 |
| 下文示例中的完整语言表面 | **已设计** | 很多例子是目标语法，不一定已经被当前代码接受 |
| 跨 shard 的语言原语（`notify`、`consistent`） | **已设计** | 运行时方向由本文定义，应将其视为目标契约 |
| 外部状态后端（`backend: .redis`） | **已设计** | 不是当前仓库已经承诺可用的能力 |
| 完整 `.rut` 程序的零停机热重载 | **部分设计 / 运行时有片段** | 运行时方向明确，但语言级全流程尚未闭环 |

### 文档拆分计划

长期来看，这份文档应拆成：

- `LANG_SPEC.md`：语法、类型、路由、状态语义、诊断
- `RUNTIME.md`：分片模型、I/O 后端、内存、重载、网络内部机制
- `ROADMAP.md`：未来阶段、可选能力、部署 / sidecar 扩展

在真正拆分之前，这个文件仍然作为总设计文档存在。

## 1. 项目概览

### 1.1 目标

- 用一门强类型语言替代 nginx 配置文件和 OpenResty Lua
- 尽可能在编译期捕获错误（类型错误、路由冲突、非法值）
- 让 LLM 容易生成和理解
- 高性能：目标支持 C100K+，并把延迟开销压到最低
- 支持无停机热重载
- 依赖最小化，控制力最大化

### 1.2 非目标

- 通用编程语言
- L4 负载均衡（本项目只做 L7 HTTP）
- DPDK / 内核旁路网络
- 与 nginx 配置格式兼容

---

## 2. 架构总览

```
                          ┌─────────────────────────────┐
    .rut source ───▶   │  Compiler (embedded in proc) │
                          │  parse → type check → IR     │
                          └───────┬───────────┬─────────┘
                                  │           │
                                  │           └──────────────▶ eBPF bytecode
                                  ▼                           (for firewall/XDP)
                         ┌──────────────────────┐
                         │  JIT (LLVM ORC JIT)   │
                         └──────────┬───────────┘
                                    │ native function pointers
                                    ▼
   ┌────────────────────────────────────────────────────────┐
   │                    Rutlang Runtime                    │
   │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
   │  │  Shard 0  │ │  Shard 1  │ │  Shard 2  │ │  Shard N  │  │
   │  │ io_uring  │ │ io_uring  │ │ io_uring  │ │ io_uring  │  │
   │  │ Router    │ │ Router    │ │ Router    │ │ Router    │  │
   │  │ Handlers  │ │ Handlers  │ │ Handlers  │ │ Handlers  │  │
   │  │ ConnPool  │ │ ConnPool  │ │ ConnPool  │ │ ConnPool  │  │
   │  │ Memory    │ │ Memory    │ │ Memory    │ │ Memory    │  │
   │  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
   │              share-nothing, per-core                   │
   └────────────────────────────────────────────────────────┘
```

补充：对普通 `route` / handler 路径，主要编译目标是 LLVM ORC JIT 生成的原生函数指针；
对 `firewall {}` 这类内核包过滤路径，编译目标是 eBPF bytecode，并加载到 XDP / 内核相关 hook。

### 2.1 关键决策

| 决策项 | 选择 | 理由 |
|----------|--------|-----------|
| 运行时 | 自定义 C++ 运行时（不是 Seastar） | 对这个用例来说 Seastar 过于复杂；Seastar 里真正相关的代码大约只有 30%；自定义运行时大约 5000 行，且完全可控 |
| 网络 | io_uring（优先）+ epoll（回退） | io_uring 在 Linux 6.0+ 上最优；epoll 作为旧内核（3.9+）回退；二者都使用内核 TCP 栈 |
| 线程模型 | per-core shard、share-nothing | Seastar / Envoy / nginx 已经验证过；能消除锁和竞态 |
| JIT | LLVM ORC JIT | 与 C++ 工具链一致，零 FFI 开销，支持延迟编译 |
| HTTP 解析器 | 自定义（约 500 行） | llhttp 是 callback 风格（不适合）；picohttpparser 缺少 strict mode；自定义 parser 可以直接与 Slice buffer + Arena 集成，支持 SIMD，并完全掌控严格性（anti-smuggling） |
| C++ 标准库 | `-nostdlib++`，仅 musl libc | 完整的内存控制、更快的编译 |
| 编译器参数 | `-fno-exceptions -fno-rtti` | 不为未使用的 C++ 特性承担额外开销 |

---

## 3. Rutlang 语言

这一章定义 **Rutlang 目标中的表面语言和语义**。其中有些小节描述的是尚未完全在当前前端里接通的功能。如果有疑问，应把这里的示例理解为“目标语言契约”，并结合上面的实现状态矩阵确认今天到底支持到哪里。

### 3.1 设计原则

- **借鉴 Swift 的语法风格**：`guard` 语句、命名参数、可选链、字符串插值，既干净又易读，也有利于 LLM 生成
- **HTTP 概念是原生对象**：方法、状态码、Header、URL、CIDR、媒体类型都是一等语言构造，而不是字符串
- **所有函数都在编译期内联**：没有运行时函数调用，每条路由最终编译成一个扁平状态机
- **异步对用户不可见**：没有 async / await / future / promise；用户写顺序代码，编译器识别 I/O 点并自动生成状态机
- **强类型 + 领域类型**：Duration、ByteSize、StatusCode、IP、CIDR、MediaType 在编译期校验
- **中间件就是普通函数**：返回状态码表示拒绝请求，不返回值表示放行
- **有界执行**：不支持 `while`、不支持递归，`for` 只能迭代有限集合，因此每个 handler 都有编译期可推导的执行上界，不会卡死一个 shard
- **三层模型**：`listen`（下游 / client）→ `.rut` 文件（网关逻辑）→ `upstream`（后端）。不提供 `gateway` 或 `downstream` 关键字，`.rut` 文件本身就是 gateway，`listen` 就是下游配置
- **极简关键字集合**：`func`, `let`, `var`, `const`, `guard`, `struct`, `route`, `match`, `if`, `else`, `for`, `in`, `return`, `defer`, `upstream`, `listen`, `tls`, `defaults`, `forward`, `websocket`, `fire`, `submit`, `wait`, `timer`, `init`, `shutdown`, `firewall`, `throttle`, `per`, `notify`, `import`, `using`, `as`, `and`, `or`, `not`, `nil`, `true`, `false`

### 3.2 文件扩展名

`.rut`

### 3.2.1 词法约定

```swift
// 注释 —— 仅支持行注释，不支持块注释
// This is a comment

// 字符串 —— 双引号，支持转义
"hello world"
"line one\nline two"           // 支持 \n \t \r \\ \"
"\(req.path)/\(req.method)"    // 使用 \() 做字符串插值

// 正则字面量 —— re 前缀
re"^/api/v\d+/"

// 数字字面量
42                              // i32
3.14                            // f64
0xFF                            // 十六进制整数
1_000_000                       // 允许下划线提升可读性

// Duration / ByteSize 字面量（领域类型）
500ms    1s    5m    1h    1d   // Duration
64b    1kb    16kb    1mb    1gb // ByteSize

// 语句以换行分隔 —— 不需要分号
let x = 42
let y = "hello"

// 长表达式：用括号换行续写
let result = (
    someVeryLongFunction(req, arg1: value1, arg2: value2)
)

// 布尔值
true   false   nil

// 运算符
and   or   not                  // 布尔（关键字）
&   |   ^   ~   <<   >>        // 位运算（符号）
+   -   *   /   %              // 算术
==  !=  <  >  <=  >=           // 比较
=                               // 赋值
?                               // 后缀 nil 检查（x?）
?.                              // 可选链（x?.method）
??                              // 空值合并（x ?? default）
!                               // 逻辑非（`not` 的别名）
@                               // 装饰器前缀
=>                              // 单表达式、隐式返回
->                              // 函数返回类型
```

### 3.3 类型系统

#### 3.3.1 内建领域类型

HTTP 相关概念是原生类型，并带有成员函数。它们都由运行时 C++ 内建结构体实现：字面量在编译期校验，访问时零额外开销。

**IP** —— IPv4 / IPv6 地址

```swift
let ip = req.remoteAddr              // IP
ip.v4?                               // bool —— 是否是 IPv4
ip.v6?                               // bool —— 是否是 IPv6
ip.isPrivate                         // bool —— RFC1918（10.x、172.16.x、192.168.x）
ip.isLoopback                        // bool —— 127.0.0.0/8 或 ::1
ip.in(10.0.0.0/8)                    // bool —— CIDR 包含关系
ip.octets                            // [u8] —— 4 或 16 字节
ip as string                         // "10.0.0.1"
"10.0.0.1" as IP                     // Result<IP>
```

**CIDR** —— 网段

```swift
let cidr = 10.0.0.0/8               // CIDR 字面量
cidr.network                         // IP —— 网络地址
cidr.prefix                          // i32 —— 前缀长度（8）
cidr.contains(req.remoteAddr)        // bool
cidr as string                       // "10.0.0.0/8"
```

**Duration** —— 时间间隔

```swift
let d = 30s                          // Duration 字面量（也支持：ms、m、h、d）
d.ms                                 // i64 —— 30000
d.seconds                           // i64 —— 30
d.minutes                            // f64 —— 0.5
// 算术：d + 1s, d - 500ms, d * 2, d > 1m, d == 30s
```

**ByteSize** —— 数据大小

```swift
let b = 16kb                         // ByteSize 字面量（也支持：b、mb、gb）
b.bytes                              // i64 —— 16384
b.kb                                 // f64 —— 16.0
b.mb                                 // f64 —— 0.015625
// 算术：b + 1kb, b > 1mb, b == 16kb
```

**StatusCode** —— HTTP 状态码

```swift
let s = resp.status                  // StatusCode
s.code                               // i32 —— 200
s.isSuccess                          // bool —— 2xx
s.isRedirect                         // bool —— 3xx
s.isClientError                      // bool —— 4xx
s.isServerError                      // bool —— 5xx
```

**Method** —— HTTP 方法

```swift
req.method                           // Method
req.method == .GET                   // bool
req.method as string                 // "GET"
```

**MediaType** —— content type

```swift
let mt = req.contentType             // MediaType
mt.type                              // string —— "application"
mt.subtype                           // string —— "json"
mt as string                         // "application/json"
```

**Time** —— 时间戳

```swift
let t = now()                        // Time
t.unix                               // i64 —— Unix 秒级时间戳
t.unixMs                             // i64 —— Unix 毫秒级时间戳
t as string                          // ISO 8601
now() - t                            // Duration —— 时间差
t + 1h                               // Time —— 加上 duration
```

**Regex** —— 编译后的正则模式

```swift
let r = re"^/api/v\d+"              // 正则字面量，编译期校验
```

**Port** —— 1..65535

```swift
let p = :8080                        // Port 字面量
p.number                             // i32 —— 8080
```

#### 3.3.2 用户自定义类型

```swift
struct User {
    id: string
    role: string
    name: string
}

struct Order {
    items: [OrderItem]
    total: f64
}

struct OrderItem {
    sku: string
    qty: i32
    price: f64
}
```

#### 3.3.3 元组

有序、定长、可异构的集合，布局在编译期已知。

```swift
let pair = (200, "ok")                       // (i32, string)
let triple = (user, orders, stock)           // (User, [Order], Stock)

// 解构
let (status, msg) = pair

// 下标访问
let first = pair.0                           // i32
let second = pair.1                          // string
```

它也可作为 `wait()` 返回多个 handle 的返回类型。通过 Arena 分配，不需要额外堆分配。

#### 3.3.4 Request 对象

Request 是内建类型。标准 HTTP header 以原生属性暴露，并带有正确的类型：

```swift
// 标准 header —— 属性访问，类型正确
req.method              // Method
req.path                // string
req.remoteAddr          // IP
req.contentLength       // ByteSize（不是 string）
req.contentType         // MediaType（不是 string）
req.authorization       // string?（可选 —— 该 header 可能不存在）
req.host                // string
req.userAgent           // string
req.origin              // string?
req.ifModifiedSince     // Time?
req.accept              // MediaType?

// 自定义 header —— 通过 header 名访问
req.X-Request-ID        // string?
req.X-User-ID           // string?
req.X-Timestamp         // string?

// 设置 header —— 直接赋值
req.X-User-ID = "123"
req.X-Request-ID = uuid()

// 路由参数 —— path capture 自动变成 req 属性
// 路由：get /users/:id/posts/:postId
req.id                  // string（来自 :id）
req.postId              // string（来自 :postId）

// Query string
req.queryString         // string? —— 原始 query string："page=1&limit=20"
req.query("page")       // string? —— 单值 query 参数
req.query("tags")       // [string]? —— 多值参数（?tags=a&tags=b）

// Body
req.body(User)          // 把 body 解析成 User 结构体 → Result<User>
req.bodyRaw             // 原始 body 字符串 → Result<string>
req.bodyRaw = newBody   // 在 forward 之前替换 body（重新计算 Content-Length）

// Cookie
req.cookie("session_id") // string?

// 多值 header
req.getAll("Accept")    // [string] —— 某个 header 的全部值
req.add("X-Tag", "a")   // 追加（不替换已有值）

// request 级上下文 —— 类型化 struct，由中间件和 handler 共享
req.ctx.userId          // 来自用户声明的 Ctx struct 字段
req.ctx.startTime       // 由装饰器设置，在 handler 中读取
```

request context `req.ctx` 需要用户先声明 `Ctx` 结构体：

```swift
struct Ctx {
    userId: string
    userRole: string
    startTime: Time
}
```

编译器会检查：handler 里读取的字段，是否已经在中间件链上的装饰器里被设置。访问未设置字段属于编译错误。

#### 3.3.5 Response 对象

```swift
// 简单响应
return 200                           // 空 body
return 401, "custom message"         // 带字符串 body
return 200, json(data)               // 带 JSON body

// 带 header —— 构造 response 对象，避免 { } 歧义
let resp = response(429)
resp.Retry-After = "60"
return resp

let resp = response(200)
resp.Content-Type = "application/json"
resp.body = json(stats())
return resp

// 重定向
let resp = response(301)
resp.Location = "https://example.com\(req.path)"
return resp

// Response 上的多值 header
resp.add("Set-Cookie", "a=1; Path=/")
resp.add("Set-Cookie", "b=2; Path=/")

// 删除 header
resp.Server = nil
```

`response(status)` 是一个内建函数，用来创建 Response 对象。`{ }` 只用于代码块，绝不用于构造 response。

#### 3.3.6 状态类型

所有持久状态都声明为顶层的强类型容器，并带有编译期已知的容量上界。这个设计受 eBPF map 启发：类型化、有界，默认 per-shard。

**Hash<K, V>** —— 通用键值存储。

```swift
let sessions = Hash<string, Session>(capacity: 50000, ttl: 30m)

sessions.set(sid, user)
let user = sessions.get(sid)       // V?
sessions.delete(sid)
sessions.contains(sid)             // bool
```

**LRU<K, V>** —— 满时按照 LRU 淘汰的键值存储。

```swift
let responseCache = LRU<string, CachedResponse>(capacity: 10000, ttl: 5m)

responseCache.set(key, resp)
let cached = responseCache.get(key)   // V? —— 命中会刷新访问时间
```

可选参数 `coalesce: true` —— 请求合并（singleflight）。在 cache miss 时避免羊群效应：只有一个请求真正去回源，其余请求等待结果，和 nginx 的 `proxy_cache_lock` 是同一模式。

```swift
let cache = LRU<string, string>(capacity: 10000, ttl: 5m, coalesce: true)

get /users/:id {
    let key = "/users/\(req.id)"
    let cached = cache.get(key)      // miss + 有 in-flight 请求 → 自动等待首个请求
    if cached? { return 200, cached }
    let resp = forward(userService, load_balance: .roundRobin, buffered: true)
    cache.set(key, resp.body)        // 存入结果并唤醒所有等待连接
    return resp
}
```

实现方式：per-shard、单线程。在 `cache.get()` miss 且同 key 已经有挂起请求时，运行时会挂起连接（挂入 intrusive linked list）。在 `cache.set()` 时，用值恢复所有 waiter。由于每个 shard 单线程，不需要 mutex。

**Set<T>** —— 成员测试。

```swift
let blacklist = Set<IP>(capacity: 100000)
let trustedNets = Set<CIDR>(capacity: 1000)

blacklist.contains(req.remoteAddr)     // bool
trustedNets.contains(req.remoteAddr)   // bool —— CIDR set 会对 IP 做最长前缀匹配
blacklist.add(ip)
blacklist.remove(ip)
```

编译器会按元素类型选择实现：`Set<IP>` / `Set<string>` 用 hash set，`Set<CIDR>` 用 LPM trie（最长前缀匹配树）。

**Counter<K>** —— 限流计数器。支持两种算法：

```swift
// 滑动窗口（默认）—— “窗口内最多 N 个请求”
let apiLimits = Counter<IP>(capacity: 100000, window: 1m)
apiLimits.incr(req.remoteAddr)         // +1，返回窗口内当前计数
apiLimits.get(req.remoteAddr)          // 当前窗口内计数
guard apiLimits.get(req.remoteAddr) <= 1000 else { return 429 }

// Token bucket —— “速率 N/min，允许突发 B”
let burstLimits = Counter<IP>(capacity: 100000, rate: 100, burst: 20)
guard burstLimits.take(req.remoteAddr) else { return 429 }
// take：消费 1 个 token，空时返回 false
// 以 100/min 的速率回填，最多积累 20 个 token
```

编译器通过参数推导算法：有 `window:` 表示滑动窗口；有 `rate:` + `burst:` 表示 token bucket。

**Bloom<T>** —— 概率型集合，适合大基数场景，节省内存。没有假阴性，但会有假阳性。

```swift
let seenRequests = Bloom<string>(capacity: 1000000, errorRate: 0.01)

seenRequests.add(key)
seenRequests.mayContain(key)           // bool —— “不在”是确定的，“在”可能是假阳性
```

适用场景：请求去重、防缓存穿透、大规模黑名单。

**Bitmap** —— 定长位图。

```swift
let features = Bitmap(size: 256)

features.set(12)                       // 置位
features.clear(12)                     // 清位
features.test(12)                      // bool
features.count()                       // popcount —— 已置位 bit 数量
```

适用场景：feature flag、upstream 健康位、紧凑布尔数组。

**通用参数：**

| 参数 | 适用对象 | 描述 |
|-----------|-----------|-------------|
| `capacity:` | 所有（必填） | 最大条目数，编译期上界 |
| `ttl:` | Hash、LRU、Counter | 过期时间；对 Counter 来说 ttl 就是滑动窗口 |
| `window:` | Counter（必填） | ttl 的别名，但更推荐给 Counter 用 |
| `errorRate:` | Bloom（必填） | 假阳性率，决定内存占用 |
| `size:` | Bitmap（必填） | 位图 bit 数 |
| `persist: true` | 所有 | 在热重载中保留数据；若 struct 布局变化则编译报错 |
| `consistent: true` | Hash、Set、Counter | 按 key hash 把操作路由到 owner shard；提供强一致，但有 SPSC 往返成本；编译器会发 warning，可用 `// rut:allow(consistent)` 抑制 |
| `coalesce: true` | LRU | 请求合并 —— cache miss 且同 key 已有 in-flight 请求时挂起等待，而不是再发重复回源请求 |
| `backend: .redis(addr)` | Hash、Counter、Set | 通过外部存储做跨节点状态同步；per-shard 状态退化为本地 cache，Redis 成为真实来源 |

**所有状态默认都是 per-shard。** 每个 shard 持有自己的一份独立副本，单线程访问、零锁。per-shard 计数器是近似的（等效 limit ≈ `limit × shard_count`）。

**跨 shard 通信：`notify`**

`notify` 是 Rutlang 暴露的唯一跨 shard 原语。两种形式：

```swift
notify all expr                    // 所有 shard —— 最终一致
notify(key) expr                   // hash(key) → owner shard —— 定向发送

let blacklist = Set<IP>(capacity: 100000)

post /admin/ban {
    let ip = req.body(IP)
    guard let ip else { return 400 }
    blacklist.add(ip)              // 本地 shard —— 立即生效
    notify all blacklist.add(ip)   // 其他 shard —— 下一个 event loop tick 生效
    return 200
}
```

- `notify all` —— 向其余 N-1 个 shard 广播，最终一致
- `notify(key)` —— 根据 key 的 hash 选出 owner shard，只发给那个 shard

实现：每个 shard 对之间有一个无锁的 SPSC（single-producer single-consumer）ring buffer。`notify` 用 `release` 语义的 tail 更新和 `relaxed` store 入队；接收 shard 在每个 event loop tick 上用 `acquire` 语义读取 tail 并 drain 队列。不用 `seq_cst`，不需要全栅栏，也避免 cache line 竞争（head 和 tail 分在不同 cache line）。

成本：`notify all` = N-1 次 relaxed 写；`notify(key)` = 1 次 relaxed 写。传播延迟大约是一个 event loop tick（微秒级）。

**强一致：`consistent: true`**

对于全局精确限流等必须强一致的状态，可声明 `consistent: true`。操作会按 key hash 路由到 owner shard，由 owner shard 顺序处理 —— 没有锁，只有一次 SPSC 往返。

```swift
// rut:allow(consistent)
let exactLimits = Counter<IP>(capacity: 100000, window: 1m, consistent: true)

get /api/*path {
    // 编译器生成：hash(remoteAddr) → owner shard → SPSC send → yield → receive
    exactLimits.incr(req.remoteAddr)
    guard exactLimits.get(req.remoteAddr) <= 1000 else { return 429 }
    return forward(userService, load_balance: .roundRobin)
}
```

成本：当当前 shard != owner shard 时，需要 1 次 SPSC 往返（若正好是 owner shard，本地操作免费）。编译器会发出 warning，要求用户用 `// rut:allow(consistent)` 明确确认。

**三级成本模型：**

| 模式 | 声明方式 | 成本 | 一致性 |
|------|-------------|------|-------------|
| per-shard | 默认 | 零 | 近似 |
| notify all | `notify all expr` | N-1 次 SPSC 写 | 最终一致 |
| notify(key) | `notify(key) expr` | 1 次 SPSC 写 | 最终一致，定向 |
| consistent | `consistent: true` | 1 次 SPSC 往返 | 强一致 |

三者本质上都建立在 SPSC 消息传递之上。没有 atomics 级别的共享状态，没有 STM，没有锁。

**跨节点状态：`backend:` 参数**

per-shard 和跨 shard 状态只在单个 Rut 进程内有效。如果多个 Rut 实例需要共享状态（例如集群级限流），就使用 `backend:` 把状态同步到外部存储：

```swift
// 仅进程内（默认）—— 快，但近似
let limits = Counter<IP>(capacity: 100000, window: 1m)

// 通过 Redis 做跨节点共享 —— 精确集群级计数
let globalLimits = Counter<IP>(capacity: 100000, window: 1m, backend: .redis("redis:6379"))

// 跨节点 session store
let sessions = Hash<string, Session>(capacity: 100000, ttl: 30m, backend: .redis("redis:6379"))
```

使用 `backend:` 后，per-shard 状态退化为本地缓存层。写入同时落本地和 Redis（异步 TCP）；读取先查本地，miss 再回 Redis。运行时负责连接池与序列化。

成本：Redis 往返大约 100μs，而本地状态访问大约 10ns。只有真正需要集群级一致性时才值得启用。

##### 3.3.6.1 状态失败与顺序语义

上面的状态 API 还需要显式的失败语义。否则语法是清楚的，但契约依然不完整。

**顺序性**

- 某个 shard 发往某个目标 shard 的操作，按发送顺序处理
- `notify(key)` 只在该 key 对应的所有操作都 hash 到同一个 owner shard 时，才自然保持 per-key 顺序
- `notify all` **不**提供跨所有 shard 的全局总序

**队列压力**

- 只有当程序显式选择 lossy 模式时，`notify` 才能是 best-effort
- 默认语言契约：如果跨 shard 队列已满，该操作应在当前请求路径上表现为运行时失败，而不是静默丢弃
- 未来也许可以提供 `notify all?, lossy: true` 之类语法，但“默认静默丢消息”不能成为默认行为

**`consistent: true`**

- 一个强一致操作，要么在 owner shard 上完成并返回结果，要么在请求可见层面失败
- 跨 shard 往返超时必须表现为运行时失败，而不是“超时但成功”
- 通过 owner shard 路由的读写，应遵守 owner shard 上的程序顺序

**外部后端**

- `backend:` 会把一致性模型从纯进程内语义，切换成由外部后端介导的语义
- 对 `backend: .redis(...)` 的默认契约应是 write-through 意图；若后端写失败，除非 API 明确允许 degraded-local mode，否则失败必须向请求暴露
- 只有当本地 cache 条目仍满足声明的 TTL / freshness 规则时，读取才可以直接命中本地缓存

**重载 / 关闭**

- 热重载不能静默丢弃已经确认完成的强一致操作
- 处于 in-flight 的 best-effort `notify` 操作，在 shutdown 期间可以被丢弃，但前提是该 API 已经明确声明自己不是 durable
- 持久状态 schema 不兼容时，应作为编译期重载拒绝，而不是尝试 best-effort 迁移

这些规则是刻意保守的。它们把语言契约收得比当前实现更严，避免某些运行时上的临时捷径意外上升为公开语义。

#### 3.3.7 错误处理：Result 与 guard

没有异常。没有 try/catch。所有可能失败的操作都返回 `Result<T>`，其中要么是值，要么是错误消息。调用者 **必须** 用 `guard let` 解包 Result；如果代码忽略一个 Result，编译器应直接拒绝。

**Result 与 Optional 的区别：**
- `string?`（Optional）—— 值可能不存在，但这不是错误。例如某个可选 header。
- `Result<User>` —— 操作可能失败，并携带错误消息。例如 body 解析。

**Nil 处理 —— 四种操作符：**

| 语法 | 名称 | 返回值 | 含义 |
|--------|------|---------|---------|
| `x?` | nil 检查 | `bool` | `x != nil` |
| `x?.method` | 可选链 | `T?` | 若 x 为 nil → nil，否则 → x.method |
| `x ?? default` | 空值合并 | `T` | 若 x 为 nil → default，否则 → x |
| `guard let x else { return N }` | 解包或拒绝 | `T` | 若 x 为 nil → 退出 handler |

```swift
// x? —— 检查是否存在（bool）
guard req.authorization? else { return 401 }
if req.origin? {
    resp.Vary = "Origin"
}

// x?.method —— 可选链（nil 传播）
let len = req.authorization?.len               // i32? —— 没有 header 时为 nil
let ok = req.authorization?.hasPrefix("Bearer") // bool? —— 没有 header 时为 nil

// x ?? default —— 空值合并（提供默认值）
let name = req.query("name") ?? "anonymous"
let page = parseInt(req.query("page") ?? "1")

// guard let —— 解包或早退
guard let token = req.authorization else { return 401 }
// token 现在是 string，可在后续正常使用

// Result —— 操作可能失败
let user = req.body(User)                  // Result<User>
guard let user else { return 400 }         // 丢弃错误消息
guard let user else { return 400, user.error }  // 在响应里带上错误消息
guard let user else {
    log.warn("bad body", { error: user.error })
    return 400, "invalid request body"
}
```

**不同操作对应的 Result 类型：**

| 操作 | 返回类型 | 常见 guard 写法 |
|-----------|-------------|---------------|
| `req.body(T)` | `Result<T>` | `guard let x else { return 400 }` |
| `get/post http://...` | `Result<Response>` | `guard let res else { return 502 }` |
| `jwtDecode(token, secret:)` | `Result<Claims>` | `guard let claims else { return 401 }` |
| `forward(upstream, load_balance: .roundRobin)` | 内建，失败时返回 502 | 不需要 guard |
| `req.authorization` | `string?`（Optional） | `guard let x else { return 401 }` |
| `req.query("key")` | `string?`（Optional） | `guard let x else { return 400 }` |

**编译期强制：** 如果一个 Result 被赋给 `let`，但后续没有 `guard let ... else`，编译器就报错：

```swift
let user = req.body(User)
forward(users, load_balance: .roundRobin)
// ERROR: Result<User> must be unwrapped with 'guard let user else { return ... }'
```

**运行时错误**（如除零、数组越界）被视为编程错误 —— 应直接返回 500，不提供恢复机制。

#### 3.3.8 编译期常量

`const` 声明一个 **必须在编译期计算** 的值。结果会直接嵌入二进制，没有运行时成本。

```swift
const secretHash = sha256(env("STATIC_SECRET"))
const jwtPublicKey = env("JWT_PUBLIC_KEY")
const maxItems = 100
const apiPrefix = "/api/v1"
```

`const` 表达式只能由以下内容组成：字面量、`env()`、纯函数（sha256、base64、字符串操作等）以及其他 `const` 值。I/O 在 `const` 中属于编译错误：

```swift
const x = sha256(env("KEY"))              // ✅ 纯函数 + env
const y = get http://config/value         // ❌ 编译错误：const 中不允许 I/O
```

即使没有 `const`，如果一个 `let` 在编译期可计算，编译器也应自动做常量折叠。`const` 的意义是显式断言：“它必须在编译期得到；做不到就报错。”

#### 3.3.9 控制流约束

Rutlang 保证有界执行 —— 每个 handler 的执行上界都可在编译期推导出来。这可避免一个有 bug 的 handler 卡死整个 shard。

- **`let`** —— 默认不可变绑定
- **`var`** —— 可变绑定，但 **仅允许 handler 局部使用**。顶层不允许 `var`。这样可以保护 share-nothing：没有全局可变状态，也没有跨 shard 可变状态
- **只支持 `for ... in`** —— 只能迭代有限集合（数组、struct 字段等），不支持 `while`、不支持无限 `loop`
- **不支持 `break` / `continue`** —— 每轮迭代都必须完整执行
- **不支持递归** —— 所有函数在编译期内联；函数调用自身属于编译错误
- **不支持闭包** —— 没有一等函数、没有回调、没有隐式捕获变量

```swift
// var —— handler 局部可变变量
get /api/data {
    var score = 0                          // ✅ 局部，任意类型
    var msg = "violations:"
    if input.matches(re"(?i)UNION\s+SELECT") {
        score += 5
        msg = "\(msg) sql_injection"
    }
    guard score <= 10 else { return 403, msg }
    return forward(userService, load_balance: .roundRobin)
}

// ❌ 顶层 var —— 编译错误
var globalCounter = 0                      // ERROR: var not allowed at top level

// OK —— 对数组做有界迭代
for item in order.items {
    guard item.qty > 0 else { return 400 }
}

// 编译错误 —— 不支持 while
while queue.hasNext() { ... }

// 编译错误 —— 不支持递归
func foo(_ req: Request) {
    foo(req)    // ERROR: recursive call detected
}
```

**`defer` —— 任意退出路径上的清理**

`defer` 注册一个语句，使其在 handler 退出时执行，不论走的是哪条 `return` 路径。多个 `defer` 按逆序（LIFO）执行。这个机制受 Go / Swift / Zig 启发。

```swift
get /api/data {
    activeConns.incr(req.remoteAddr)
    defer activeConns.decr(req.remoteAddr)     // 任意退出路径都执行

    let start = now()
    defer log.info("done", duration: now() - start)  // 在上一个 defer 之后执行（LIFO）

    guard req.authorization? else { return 401 }      // defer 仍然执行
    guard req.contentLength <= 1mb else { return 413 } // defer 仍然执行
    return forward(userService, load_balance: .roundRobin)                        // defer 仍然执行
}
```

编译器会把 `defer` 在每个 `return` 处直接展开。没有运行时栈，没有额外分配，纯粹是编译期代码复制。

### 3.4 语法

#### 3.4.1 Listening、TLS 和 Upstream

**Listening**

```swift
// 最简单形式
listen :80

// 带连接级安全控制（抗 DDoS / slowloris）
listen :443 {
    maxConns: 100000             // 全局最大连接数
    maxConnsPerIP: 256           // 每个 IP 的连接数上限
    headerTimeout: 10s           // header 必须在此时间内到达
    bodyTimeout: 30s             // body 必须在此时间内到达
    idleTimeout: 60s             // keep-alive 空闲超时
    maxHeaderSize: 8kb           // header 总大小上限
    maxHeaderCount: 100          // header 数量上限
    maxUrlLength: 4kb            // URL 长度上限
    minRecvRate: 1kb/s           // 收包速率低于这个值则断开
    strictParsing: true          // 拒绝歧义 HTTP（anti-smuggling）
}

// 用于 metrics / admin 的内部端口
listen :9090

// PROXY Protocol —— 解析 HAProxy PROXY v1/v2，从而在 L4 负载均衡后拿到真实客户端 IP
// 解析后，req.remoteAddr 反映原始客户端 IP，而不是负载均衡器的 IP
listen :443, proxyProtocol: true
```

**TLS 证书（SNI）**

TLS 证书声明是顶层语句，和路由分开。编译器会根据这些声明构造 SNI callback table。优先级：精确域名 > 通配域名 > default。

```swift
// 每域名证书 —— 编译器构造 SNI lookup table
tls "api.example.com",   cert: env("API_CERT"),      key: env("API_KEY")
tls "admin.example.com", cert: env("ADMIN_CERT"),     key: env("ADMIN_KEY")

// 通配证书 —— 匹配所有未被精确条目命中的 *.example.com
tls "*.example.com",     cert: env("WILDCARD_CERT"),  key: env("WILDCARD_KEY")

// 默认证书 —— 当 SNI 不匹配任何域名，或客户端未发送 SNI 时使用
tls default,             cert: env("DEFAULT_CERT"),   key: env("DEFAULT_KEY")

// 单域名简写（只有一个证书时）
tls cert: env("CERT"), key: env("KEY")

// OCSP stapling —— 运行时周期性从 CA 拉取 OCSP 响应，
// 并在 TLS 握手里附带，用于客户端证书吊销检查
tls "api.example.com", cert: env("CERT"), key: env("KEY"), ocsp: true
```

**全局默认值**

所有路由共享的配置。若某个 upstream 或 proxy 单独设置了值，则覆盖这些默认值。

```swift
defaults {
    forwardBufferSize: 16kb      // 每连接 forward buffer 大小
    clientMaxBodySize: 10mb      // 默认请求体大小上限
    compress: .auto(             // 响应压缩
        types: [text/html, text/css, application/json, application/javascript]
        minSize: 256b
        level: 4
    )
    errorPages: "/var/www/errors/"   // 自定义错误页：{dir}/{status}.html
    tracing: .otlp(endpoint: "http://collector:4318")  // 或 .zipkin(...) 或 .off
    cache: .auto(capacity: 10000, maxSize: 10mb)       // RFC 7234 自动缓存
}
```

**错误页：** 当某个 handler 返回 `>= 400` 的状态码时，运行时会去查找 `{errorPages}/{status}.html`。如果找到，就把该文件内容作为 response body；找不到则返回默认纯文本。只要一行配置，不需要写额外 Rutlang 代码。

**请求优先级：** 在高负载下，运行时可以先丢弃低优先级请求。通过在 route 或 group 上使用 `@priority` 装饰器配置：

```swift
route {
    @priority(.high)
    api.example.com/payments { ... }

    @priority(.normal)                    // 默认
    api.example.com/users { ... }

    @priority(.low)
    api.example.com/analytics { ... }
}
```

当 accept queue 或 per-shard 连接数超过阈值时，运行时会先以 503 拒绝新的 `.low` 优先级连接；如果负载继续上升，再拒绝 `.normal`。`.high` 最后才被 shed。

压缩会依据 `Accept-Encoding` header 和 `types` 列表自动应用。若某个 route 不想压缩（例如已经压缩过的图片，或流式响应），可在 response 里显式设置 `compress: .off`：

```swift
get /files/:id {
    forward(storageService, load_balance: .roundRobin, compress: .off)          // 对这个 proxy 禁用压缩
}

get /images/*path {
    read(root: "/var/www/images", compress: .off)  // 图片本身已经压缩过
}
```

**Upstream**

```swift
let users = upstream {
    "10.0.0.1:8080", weight: 3
    "10.0.0.2:8080"
    health: .active(get: "/ping", every: 5s)              // 主动健康检查 —— timer probe
    health: .passive(failures: 5, recover: 30s)            // 被动健康检查 —— 连续错误后标记不健康
    breaker: .consecutive(failures: 5, recover: 30s)
    retry: .on([502, 503, 504], count: 2, backoff: 100ms)
    connectTimeout: 3s           // 覆盖默认值
    readTimeout: 30s             // upstream 读超时
    sendTimeout: 10s             // upstream 写超时
    keepalive: 64                // 每 shard 最大空闲连接数
}

// 带 mTLS 的 upstream —— 连接时出示客户端证书
let internalService = upstream {
    "10.0.0.5:8443"
    tls: .mtls(cert: env("CLIENT_CERT"), key: env("CLIENT_KEY"), ca: env("CA_CERT"))
}

let orders = upstream { "10.0.1.1:8080" }
```

**按转发点显式选择负载均衡策略：**

`upstream` 只声明后端集合和连接配置。每个 `forward` 必须填写 `load_balance`，
单后端和宿主绑定的 upstream 也不能省略；不提供默认值、继承或别名。
当前只接受 `.roundRobin` 与 `.leastRequests`，其他算法尚未实现。

```swift
upstream api {
    backends: ["127.0.0.1:9001", "127.0.0.1:9002"]
}
route GET "/catalog" {
    return forward(api, load_balance: .roundRobin)
}
route POST "/jobs" {
    return forward(api, load_balance: .leastRequests)
}
```

轮询游标按转发点与 shard 隔离；最少请求策略统计该 shard 上同一 upstream 的
在途请求/RPC，跨路由共享，流式 gRPC 按 RPC 计数。请求数相同时按该转发点轮换。
完成、失败、取消、重置或关闭时只释放一次计数；重试先释放失败尝试，再按原策略选择。
健康后端存在时跳过被剔除的端点；全部被剔除时保留现有继续尝试的行为。
完整契约见 [语言卡](docs/language-card.md#explicit-load-balancing-at-each-forward-call)。

**⏳ 自定义负载均衡（仅设计，尚未实现）：**

用户也可以用 Rutlang 自己实现算法。不是 `forward(upstream, load_balance: .roundRobin)`，而是先遍历 `upstream.servers` 选一个 target，再对具体地址 `forward`：

```swift
// 自定义：按 header 指定的目标名路由
func selectByHeader(_ req: Request, up: Upstream) -> Server {
    for server in up.servers {
        if server.addr == req.X-Target-Server {
            return server
        }
    }
    return up.servers[0]    // fallback 到第一个
}

get /custom {
    let target = selectByHeader(req, up: users)
    return forward(target, load_balance: .roundRobin)
}
```

`upstream.servers` 暴露 target 列表，类型是 `[Server]`。`Server` 包含字段：`addr`（string）、`weight`（i32）、`healthy`（bool）、`activeConns`（i32）、`latencyEwma`（Duration）。用户可以读取这些字段，自定义任意选择逻辑。

**健康检查模式：**

- `.active(get: path, every: Duration)` —— 定时对每个 target 发 HTTP probe
- `.passive(failures: N, recover: Duration)` —— 运行时统计每个 target 的 `forward()` 错误；连续 N 次失败后标记不健康，在 Duration 后恢复

**Slow start：**

```swift
let backend = upstream {
    "10.0.0.1:8080"
    slowStart: 30s    // target 恢复健康后，在 30s 内把权重从 0 线性升到配置值
}
```

当 target 从 unhealthy 恢复后，有效权重会在 `slowStart:` 时间内从 0 线性增加到配置值，避免把刚启动好的服务瞬间压满。

**Outlier detection：**

比被动健康检查更复杂 —— 它按时间窗口跟踪各 target 的成功率，把明显低于平均水平的 target 剔除。

```swift
let backend = upstream {
    "10.0.0.1:8080"
    "10.0.0.2:8080"
    outlier: .successRate(
        threshold: 0.9,         // 成功率低于 90% 则 eject
        interval: 30s,          // 评估窗口
        minRequests: 100        // 至少达到这个样本量才评估
    )
}
```

**Retry budget：**

防止重试风暴 —— 将总重试量限制在正常流量的一定比例以内。

```swift
let backend = upstream {
    retry: .on([502, 503], count: 2, backoff: 100ms)
    retryBudget: .percent(20)   // 重试总量不能超过正常请求量的 20%
}
```

**Locality-aware routing：**

优先选择和当前 shard 位于同一 zone / region 的 upstream，以减少跨 AZ 延迟和流量成本。

```swift
let backend = upstream {
    "10.0.0.1:8080", zone: "us-east-1a"
    "10.0.0.2:8080", zone: "us-east-1b"
    "10.0.0.3:8080", zone: "us-west-2a"
    locality: .preferLocal      // 优先选择和当前 shard 同 zone 的 target
}
```

**Happy Eyeballs（RFC 8305）：**

双栈连接竞争 —— IPv4 和 IPv6 同时尝试，先连上谁就用谁。

```swift
let backend = upstream {
    "api.example.com:8080"      // DNS 会返回 A + AAAA
    happyEyeballs: true         // IPv4 / IPv6 并发 connect，使用先成功者
}
```

**Cluster warming：**

新 target 在第一次健康检查通过之前，不接收任何流量。

```swift
let backend = upstream {
    health: .active(get: "/ping", every: 5s)
    warming: true               // 健康检查通过前不参与路由
}
```

**完整 upstream 示例：**

```swift
let userService = upstream {
    "10.0.0.1:8080", weight: 3, zone: "us-east-1a"
    "10.0.0.2:8080", weight: 1, zone: "us-east-1b"
    health: .active(get: "/ping", every: 5s)
    health: .passive(failures: 5, recover: 30s)
    outlier: .successRate(threshold: 0.9, interval: 30s, minRequests: 100)
    breaker: .consecutive(failures: 5, recover: 30s)
    retry: .on([502, 503], count: 2, backoff: 100ms)
    retryBudget: .percent(20)
    connectTimeout: 3s
    readTimeout: 30s
    keepalive: 64
    slowStart: 30s
    warming: true
    locality: .preferLocal
    happyEyeballs: true
    tls: .mtls(cert: env("CLIENT_CERT"), key: env("CLIENT_KEY"), ca: env("CA_CERT"))
}
```

#### 3.4.2 函数（中间件与辅助函数）

所有函数都在编译期内联。不存在运行时函数调用开销。

中间件有两种，由参数签名区分：
- **Request middleware**：`func f(_ req: Request)` —— 在 handler 之前执行。返回状态码表示拒绝请求，不返回值表示放行
- **Response middleware**：`func f(_ req: Request, _ resp: Response)` —— 在 handler / proxy 之后、发送给客户端之前执行。可以修改 response header、body、status

`guard` 是表达“检查通过，否则拒绝”的惯用方式。

```swift
func auth(_ req: Request, role: string) -> User {
    guard let token = req.authorization else { return 401 }
    guard token.hasPrefix("Bearer ") else { return 401 }

    let claims = jwtDecode(token.trimPrefix("Bearer "), secret: env("JWT_SECRET"))
    guard let claims else { return 401 }
    guard claims.exp >= now() else { return 401, "token expired" }
    guard claims.role == role else { return 403 }

    req.X-User-ID = claims.sub
    req.X-User-Role = claims.role
    return User(id: claims.sub, role: claims.role)
}

func rateLimit(_ req: Request, limits: Counter<IP>, max: i32) {
    let count = limits.incr(req.remoteAddr)
    guard count <= max else { return 429 }
}

func requestId(_ req: Request) {
    if req.X-Request-ID.isEmpty {
        req.X-Request-ID = uuid()
    }
}

func cors(_ req: Request, origins: [string]) {
    let origin = req.origin
    guard origins.contains(origin) else {
        if req.method == .OPTIONS { return 403 }
        return
    }

    if req.method == .OPTIONS {
        let resp = response(204)
        resp.Access-Control-Allow-Origin = origin
        resp.Access-Control-Allow-Methods = "GET, POST, PUT, DELETE"
        resp.Access-Control-Allow-Headers = "Content-Type, Authorization"
        resp.Access-Control-Max-Age = "86400"
        return resp
    }

    req.Access-Control-Allow-Origin = origin
    req.Vary = "Origin"
}

func verifySig(_ req: Request, secret: string) {
    guard let ts = req.X-Timestamp else { return 401 }
    guard now() - time(ts) <= 5m else { return 401, "expired" }

    let payload = "\(req.method)\n\(req.path)\n\(ts)"
    guard hmacSha256(secret, payload).hex == req.X-Signature else {
        return 401, "bad signature"
    }
}

func ipAllow(_ req: Request, cidrs: [CIDR]) {
    guard cidrs.contains(req.remoteAddr) else {
        return 403
    }
}

func maxBody(_ req: Request, limit: ByteSize) {
    guard req.contentLength <= limit else { return 413 }
}

func concurrencyLimit(_ req: Request, active: Counter<string>, limit: i32) {
    guard active.get(req.remoteAddr) < limit else { return 503, "overloaded" }
}

// --- Response 中间件（同时接收 Request 和 Response）---

func securityHeaders(_ req: Request, _ resp: Response) {
    resp.Strict-Transport-Security = "max-age=31536000; includeSubDomains"
    resp.X-Content-Type-Options = "nosniff"
    resp.X-Frame-Options = "DENY"
    resp.X-XSS-Protection = "1; mode=block"
    resp.Referrer-Policy = "strict-origin-when-cross-origin"
    resp.Server = nil          // 去掉 server 信息
}

// --- 安全中间件示例 ---

func antiFlood(_ req: Request, perIP: Counter<IP>, global: Counter<string>) {
    guard perIP.incr(req.remoteAddr) <= 50 else { return 429 }
    guard global.incr("total") <= 10000 else { return 503 }
}

func waf(_ req: Request) {
    let path = req.path
    guard !path.contains("/../") else { return 403, "path traversal" }
    guard !urlDecode(path).contains("/../") else { return 403, "encoded traversal" }

    let input = "\(path) \(req.queryString ?? "")"
    guard !input.matches(re"(?i)UNION\s+SELECT|DROP\s+TABLE|<script|javascript:") else {
        log.warn("waf blocked", { addr: req.remoteAddr })
        return 403
    }
}

func blockBots(_ req: Request) {
    let ua = req.userAgent.lower()
    guard !ua.isEmpty else { return 403 }
    let blocked = ["bot", "spider", "crawler", "scraper"]
    for word in blocked {
        guard !ua.contains(word) else { return 403 }
    }
}
```

#### 3.4.3 UFCS（统一函数调用语法）

任何第一个参数类型为 `T` 的函数，都可以写成 `t.func(剩余参数)` 的形式调用。编译器会把 `t.func(args)` 重写成 `func(t, args)`。这只是语法糖，没有额外开销。

```swift
// 下面两种写法等价：
auth(req, role: "user")
req.auth(role: "user")

// 链式写法更自然：
req.requestId()
req.auth(role: "user")
req.rateLimit(limits: apiLimits, max: 1000)

// 不只适用于 Request，任何类型都可以：
let clean = req.path.replace(re"/+", "/")    // replace(req.path, re"/+", "/")
```

UFCS 并不是给类型动态增加方法，它只是调用约定。目标函数必须真实存在，且其第一个参数类型必须和接收者匹配。

#### 3.4.4 路由定义

`route` 是对请求做模式匹配。这个 block 分为两部分：

1. **中间件绑定**（顶部）—— `@decorator pattern` 声明
2. **路由条目**（下面）—— `method path { handler }` 或 `method path => expr`

条目之间不写逗号（沿用 Swift 风格）。

**中间件绑定：**

在 `route` block 的顶部（任何 route entry 之前），`@decorator pattern` 会把一个中间件函数绑定到所有匹配该 pattern 的路由。`*` 匹配全部。

```swift
route {
    // 中间件绑定 —— 位于 block 顶部
    @requestId *                           // 所有路由
    @waf *                                 // 所有路由
    @apiGuard api.example.com              // 作用域限定在 host
    @adminGuard admin.example.com          // 作用域限定在 host
    @maxBody(limit: 1mb) api.example.com/orders  // 作用域限定在 host + path

    // 下方开始是真正的路由条目...
}
```

`@decorator` 也可以直接贴在某条 route entry 或某个 group 上，处理 one-off 场景：

```swift
route {
    @requestId *

    @maxBody(limit: 100mb)                  // 仅这条路由
    post /files/upload => forward(storageService, load_balance: .roundRobin, streaming: true)

    get /users/:id => forward(userService, load_balance: .roundRobin)  // 会继承上面的 @requestId 绑定
}
```

**前置 / 后置中间件 —— 通过函数签名推导：**

编译器根据中间件第一个参数的类型推断其执行阶段：
- 第一个参数是 `Request` → **前置中间件**（在 handler 前）
- 第一个参数是 `Response` → **后置中间件**（在 handler 后）

```swift
// 前置 —— 第一个参数是 Request
func requestId(_ req: Request) { ... }

// 后置 —— 第一个参数是 Response
func addSecurityHeaders(_ resp: Response) {
    resp.Server = nil
    resp.X-Content-Type-Options = "nosniff"
}

// 对两者都使用同样的 @ 语法 —— 编译器自己推断
route {
    @requestId *                // Request → pre
    @addSecurityHeaders *       // Response → post

    get /users/:id => forward(userService, load_balance: .roundRobin)
}

// 展开后等价于：
//   requestId(req)              ← pre
//   handler                     ← forward
//   addSecurityHeaders(resp)    ← post
```

**后置中间件会强制 buffered mode。** 当某条用了 zero-copy `forward` 的 route 绑定了后置中间件时，编译器应自动切换为 buffered mode，并发出 warning：

```
⚠ warning: post-middleware @addSecurityHeaders forces buffered mode for
            'get /users/:id => forward(userService, load_balance: .roundRobin)'. Zero-copy disabled.
            To silence: use forward(userService, load_balance: .roundRobin, buffered: true) explicitly.
```

**条件装饰器：`@if`**

`@if(expr)` 用于按条件应用它后面的装饰器。表达式在编译期计算（`.rut` 编译时就解析 `env()`）。如果结果为 false，则该装饰器绑定会被整体消掉，不产生任何运行时开销。

```swift
route {
    @requestId *

    @if(env("ENABLE_WAF") == "true")
    @waf *

    @if(env("ENV") == "production")
    @addSecurityHeaders *

    api.example.com {
        get /users/:id => forward(userService, load_balance: .roundRobin)
    }
}
```
