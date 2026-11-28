# AGENTS.md

## 项目与资料

Rutlang 是强类型 DSL（`.rut`）与 C++23 高性能 L7 网关运行时，采用每核独立
shard、io_uring / epoll 和 LLVM ORC JIT。

- 架构与设计背景：[CLAUDE.md](CLAUDE.md)、[DESIGN.md](DESIGN.md)。
- 编写或修改语言功能前查阅 [docs/language-card.md](docs/language-card.md)；
  标记 ⏳ 的能力尚未实现，不要将设计目标当作当前支持。
- 编译器在 `src/compiler/`，JIT 在 `src/jit/`，运行时在 `src/runtime/`；
  头文件在 `include/rut/`，测试在 `tests/`，测试框架在 `testing/`。

## 核心约束

- **不轻易新增语言关键字（keyword）、依赖库（lib）或其他外部依赖。**
  优先复用现有语法、已有库和项目内部能力；确有必要新增时，说明现有能力为何不足，
  并权衡收益、复杂度和维护成本。此原则同样适用于构建、测试与工具脚本。
- 生产目标不链接 `libstdc++` 或 `libc++`。允许使用不会引入这些链接依赖的
  C++ 标准库头文件功能，例如 `std::forward`。复用项目已有容器与结果类型，
  不引入异常或 RTTI。
- 不使用普通 `new` / `malloc`；使用 Arena、SlicePool、SlabPool 等既有分配器，
  保持热路径无堆分配，并检查非拥有视图和异步 I/O 的生命周期。
- 内部一般计数和差值优先使用范围足够的有符号整数。协议、ABI、位运算和明确的模运算沿用所需类型。
  C++ 中直接映射 ABI 字段的类型用 `decltype(AbiType::field)` 派生。哈希值、标志或令牌按用途命名，
  对只允许比较或位操作的值使用限制运算符的类型；算法明确需要的模加减封装成具名操作。
  迭代器已确认未到同一有效范围的 `end` 时可用 `++`；双向迭代器已确认未到 `begin` 时可用 `--`。
  外部值先验证再转换；对加减法在运算前证明结果可表示，不依赖有符号溢出后变负。
- 状态归属单个 shard；跨 shard 使用消息传递，配置热更新沿用 RCU。
- 连接推进使用函数指针回调，后端选择使用模板；保持 io_uring / epoll 的
  `IoEvent` 语义一致，不引入协程或虚函数分派。
- `rut_runtime` 保持不依赖 LLVM，LLVM 集成集中在 `rut_jit`。
- TLS 使用 CMake 固定版本和校验和构建的静态 OpenSSL；不链接系统 OpenSSL，
  测试不依赖系统 OpenSSL CLI。普通 `rut` 构建必须通过无 C++ 标准库链接及 ELF 依赖检查；
  LLVM 编译器工具与 sanitizer 构建单独计算。
- Rutlang 遵循 **Swift-exact or absent**，不凭 Swift 经验发明语法；
  语言语义变更同步更新 `DESIGN.md`、语言卡和相关测试。

## 构建与验证

完整运行时验证需要 Linux；工具与依赖以 CMake 和 `.github/workflows/ci.yml` 为准。

```bash
./dev.sh build        # 配置并构建，主程序 build/src/rut
./dev.sh test         # 构建并运行测试
./dev.sh tidy         # clang-tidy
./dev.sh format       # clang-format 检查
./dev.sh all          # 以上全部检查
```

- 按改动范围运行相关测试；新增测试沿用现有框架并注册到 `tests/CMakeLists.txt`。
- 运行时改动关注两个后端的失败、取消、关闭和资源回收路径。
- 遵循 `.clang-format` 和 `.clang-tidy`，仅格式化受影响的文件。
- 纯文档修改检查内容与链接即可；环境不支持的检查需明确说明，不能报告为通过。

## 工作方式

先查看相关实现与测试，保留用户已有改动，避免无关重构或第三方代码变更。
交付时简要说明改了什么、如何验证，以及尚未验证的部分。
