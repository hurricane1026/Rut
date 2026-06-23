# musl-static 去风险 harness

验证 rut-node 能做成**零 `.so`、musl-static** 的二进制(TLS + Vectorscan 正则 runtime),
并**真正跑通** rut-master(编译+序列化)→ rut-node(只反序列化+扫描)的拆分。
结论见 `docs/rut-node-static-distribution.md` §5。

> 必须在带完整 musl C++ 工具链的环境里跑(Alpine / musl-cross-make)。
> Fedora 的 `musl-gcc` 是 C-only wrapper,编不了 vectorscan 的 C++。

> **链的是 vendored 库,不是系统包。** Vectorscan 与 BoringSSL 都从 `third_party/` 子模块
> 现场编译,头也走 `third_party/.../`(`-I`)。否则验的是系统 OpenSSL/发行版 vectorscan,
> 不是 rut-node 实际要发的那套。

## 文件

- `gen_db.c` —— **master 侧**:链*完整* `libhs.a`,`hs_compile` + `hs_serialize_database`
  一个小模式("foo")成可移植 DB 字节。rut-node 永不做这步。
- `derisk.c` —— **node 侧**:只链 `libhs_runtime.a`(无编译器)+ BoringSSL,反序列化 DB →
  `hs_alloc_scratch` → `hs_scan` 真扫出命中,并验 BoringSSL TLS。每步 fail-hard。
  *节点* 二进制只链 runtime —— 若它需要 compile 符号,**链接**就会失败。

## 复现(需 docker + checkout 的 submodule)

```bash
# 从仓库根目录
git submodule update --init --depth 1 third_party/boringssl third_party/vectorscan

docker run --rm -v "$PWD":/repo alpine:3.20 sh -c '
  set -e
  # build-base 给 g++;go + perl 是 BoringSSL 配置/生成所需(见其 BUILDING.md);
  # file 给 BusyBox 没有的 file(1)(下面用它确认真静态)。
  apk add --no-cache build-base cmake samurai boost-dev ragel python3 \
    pkgconf sqlite-dev linux-headers go perl file

  # 保守 ISA 基线:FAT_RUNTIME=OFF 默认 -march=native,会把 runtime 钉死在构建机的
  # AVX2/AVX512 上,older 节点跑不了。按容器架构选基线(arm64 镜像下 -march=x86-64-v2
  # 会被编译器直接拒,所以 gate 在 uname -m 上)。
  case "$(uname -m)" in
    x86_64)  VS_FLAGS="-march=x86-64-v2" ;;   # SSE4.2 基线
    aarch64) VS_FLAGS="-march=armv8-a" ;;     # ARMv8 基线
    *)       VS_FLAGS="" ;;
  esac

  # 1) vendored Vectorscan:full(给 gen_db 编译用)+ runtime(给 derisk 节点用)
  cmake -B /tmp/vs -G Ninja /repo/third_party/vectorscan \
    -DCMAKE_BUILD_TYPE=Release -DFAT_RUNTIME=OFF \
    -DCMAKE_C_FLAGS="$VS_FLAGS" -DCMAKE_CXX_FLAGS="$VS_FLAGS" \
    -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_UNIT=OFF -DBUILD_TOOLS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF
  samu -C /tmp/vs hs hs_runtime   # Alpine 的 samurai 装的是 samu,不是 ninja
  VS_FULL=$(find /tmp/vs -name libhs.a | head -1)
  VS_RT=$(find /tmp/vs -name libhs_runtime.a | head -1)

  # 2) vendored BoringSSL(不装 openssl-*;rut-node 发的就是 BoringSSL)
  cmake -B /tmp/bssl -G Ninja /repo/third_party/boringssl -DCMAKE_BUILD_TYPE=Release
  samu -C /tmp/bssl ssl crypto
  BSSL_SSL=$(find /tmp/bssl -name libssl.a | head -1)
  BSSL_CRYPTO=$(find /tmp/bssl -name libcrypto.a | head -1)
  [ -n "$VS_FULL" ] && [ -n "$VS_RT" ] && [ -n "$BSSL_SSL" ] && [ -n "$BSSL_CRYPTO" ] \
    || { echo "FAIL: vendored static libs not all built"; exit 1; }

  cd /repo/scripts/musl_derisk
  VS_INC="-I /repo/third_party/vectorscan/src -I /tmp/vs"  # /tmp/vs 提供生成的 hs_version.h
  # master 工具(允许背 C++ 运行时,链 full libhs)
  g++ -static -O2 $VS_INC gen_db.c -o /tmp/gen_db "$VS_FULL" -lpthread
  /tmp/gen_db /tmp/db.bin

  # node 二进制:只链 hs_runtime + BoringSSL;-static 真静态。
  g++ -static -O2 -ffunction-sections -fdata-sections -Wl,--gc-sections \
    $VS_INC -I /repo/third_party/boringssl/include \
    derisk.c -o /tmp/derisk_musl "$VS_RT" "$BSSL_SSL" "$BSSL_CRYPTO" -lpthread

  file /tmp/derisk_musl
  # --- 断言全部 fail-hard;在 strip *之前* 看符号表(strip 后 nm 必 0,会假阳) ---
  if readelf -d /tmp/derisk_musl | grep -q NEEDED; then
    echo "FAIL: 仍有动态依赖"; readelf -d /tmp/derisk_musl | grep NEEDED; exit 1
  fi
  echo "零 NEEDED ✓"
  # C++ 运行时/异常:operator new/delete (_Zn*/_Zd*)、STL (_ZSt/_ZNSt)、EH。
  # 只匹配 *异常处理* 的 __cxa_(throw/catch/allocate_exception/rethrow/unexpected/bad),
  # 不匹配 musl 正常的 __cxa_atexit/__cxa_finalize —— 那是 libc 退出钩子,g++ 驱动的链即便
  # 没拉进任何 STL/EH 也会带上,否则会把合法 repro 误判失败。
  # 注意:这里必须用双引号。整个脚本已被外层 sh -c 的单引号包住,内层再出现单引号会提前
  # 闭合外层(本注释也因此不含任何单引号)。此正则不含会被双引号展开的字符,双引号安全。
  CXXPAT="_ZNSt|_ZSt|_Zn[wa]|_Zd[la]|__gxx_personality|__cxa_(throw|begin_catch|end_catch|allocate_exception|free_exception|rethrow|call_unexpected|bad_)"
  cxx=$(nm /tmp/derisk_musl | grep -cE "$CXXPAT" || true)
  [ "$cxx" -eq 0 ] || { echo "FAIL: $cxx 个 C++ 运行时/异常符号"; nm /tmp/derisk_musl | grep -E "$CXXPAT"; exit 1; }
  echo "C++ 运行时符号 0 ✓"

  strip /tmp/derisk_musl
  /tmp/derisk_musl /tmp/db.bin   # 任一验证失败则非零退出
'
```

预期:`Not a valid dynamic program`(真静态)、零 NEEDED、C++ 运行时符号 0、
`derisk ok: valid_platform=HS_SUCCESS scan_hits=1 ...`。`set -e` + 各断言保证任一项不达标即非零退出。
