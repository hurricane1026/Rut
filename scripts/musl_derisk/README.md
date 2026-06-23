# musl-static 去风险 harness

验证 rut-node 能做成**零 `.so`、musl-static** 的二进制(TLS + Vectorscan 正则 runtime)。
结论见 `docs/rut-node-static-distribution.md` §5。

> 必须在带完整 musl C++ 工具链的环境里跑(Alpine / musl-cross-make)。
> Fedora 的 `musl-gcc` 是 C-only wrapper,编不了 vectorscan 的 C++。

> **链的是 vendored 库,不是系统包。** Vectorscan runtime 与 BoringSSL 都从
> `third_party/` 子模块**现场编译**;头也走 `third_party/.../`(`-I`),不装
> `vectorscan-dev`/`openssl-*`。否则验的是系统 OpenSSL/发行版 vectorscan,不是
> rut-node 实际要发的那套。

## 文件

- `derisk.c` —— 同时调 vectorscan runtime(`hs_valid_platform`/`hs_deserialize_database`/`hs_scan`)
  与 BoringSSL(`SHA256`/`SSL_CTX`),验证两者能静态链进一个零-NEEDED 的 musl 二进制。
  每个被验证步骤都 fail-hard(非零退出),`hs_deserialize/hs_scan` 用真调用强制符号引用
  (缺失则**链接**失败,而非被 `-O2` 死代码消除后照样链上)。

## 复现(需 docker + checkout 的 submodule)

```bash
# 从仓库根目录
git submodule update --init --depth 1 third_party/boringssl third_party/vectorscan

docker run --rm -v "$PWD":/repo alpine:3.20 sh -c '
  set -e
  apk add --no-cache build-base cmake samurai boost-dev ragel python3 \
    pkgconf sqlite-dev linux-headers
  # 1) vendored Vectorscan runtime(不装 vectorscan-dev)
  cmake -B /tmp/vs -G Ninja /repo/third_party/vectorscan \
    -DCMAKE_BUILD_TYPE=Release -DFAT_RUNTIME=OFF \
    -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_UNIT=OFF -DBUILD_TOOLS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF
  ninja -C /tmp/vs hs_runtime
  # 2) vendored BoringSSL(不装 openssl-*;rut-node 发的就是 BoringSSL)
  cmake -B /tmp/bssl -G Ninja /repo/third_party/boringssl -DCMAKE_BUILD_TYPE=Release
  ninja -C /tmp/bssl ssl crypto
  BSSL_SSL=$(find /tmp/bssl -name libssl.a | head -1)
  BSSL_CRYPTO=$(find /tmp/bssl -name libcrypto.a | head -1)
  [ -n "$BSSL_SSL" ] && [ -n "$BSSL_CRYPTO" ] || { echo "FAIL: BoringSSL static libs not built"; exit 1; }

  cd /repo/scripts/musl_derisk
  # 头走 vendored submodule(-I),库走现场编的 .a;-static 真静态。
  g++ -static -O2 -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -I /repo/third_party/vectorscan/src -I /repo/third_party/boringssl/include \
    derisk.c -o /tmp/derisk_musl \
    /tmp/vs/lib/libhs_runtime.a "$BSSL_SSL" "$BSSL_CRYPTO" -lpthread

  file /tmp/derisk_musl
  # --- 断言全部 fail-hard;并在 strip *之前* 看符号表(strip 后 nm 必然 0,会假阳) ---
  if readelf -d /tmp/derisk_musl | grep -q NEEDED; then
    echo "FAIL: 仍有动态依赖 (NEEDED)"; readelf -d /tmp/derisk_musl | grep NEEDED; exit 1
  fi
  echo "零 NEEDED ✓"
  cxx=$(nm /tmp/derisk_musl | grep -cE "_ZNSt|__cxa_throw|_Znwm" || true)
  [ "$cxx" -eq 0 ] || { echo "FAIL: $cxx 个 libstdc++/异常符号"; exit 1; }
  echo "libstdc++ 符号 0 ✓"

  strip /tmp/derisk_musl
  /tmp/derisk_musl   # 任一验证失败则非零退出
'
```

预期:`Not a valid dynamic program`(真静态)、零 NEEDED、libstdc++ 符号数 0、
`derisk ok: valid_platform=HS_SUCCESS ...`。脚本 `set -e` + 各断言保证任一项不达标即非零退出。
