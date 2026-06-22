# musl-static 去风险 harness

验证 rut-node 能做成**零 `.so`、musl-static** 的二进制(TLS + Vectorscan 正则 runtime)。
结论见 `docs/rut-node-static-distribution.md` §5。

> 必须在带完整 musl C++ 工具链的环境里跑(Alpine / musl-cross-make)。
> Fedora 的 `musl-gcc` 是 C-only wrapper,编不了 vectorscan 的 C++。

## 文件

- `derisk.c` —— 同时调 vectorscan runtime(`hs_valid_platform`/`hs_scan`/`hs_deserialize`)
  与 BoringSSL/OpenSSL(`SHA256`/`SSL_CTX`),验证两者能静态链进一个零-NEEDED 的 musl 二进制。
- `tls_only.c` —— 仅 TLS,用于单功能体积测量。

## 复现(需 docker + checkout 的 submodule)

```bash
# 从仓库根目录
git submodule update --init --depth 1 third_party/boringssl third_party/vectorscan

docker run --rm -v "$PWD":/repo alpine:3.20 sh -c '
  apk add --no-cache build-base cmake samurai boost-dev ragel python3 \
    pkgconf sqlite-dev openssl-dev openssl-libs-static vectorscan-dev linux-headers
  cmake -B /tmp/vs -G Ninja /repo/third_party/vectorscan \
    -DCMAKE_BUILD_TYPE=Release -DFAT_RUNTIME=OFF \
    -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_UNIT=OFF -DBUILD_TOOLS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF
  ninja -C /tmp/vs hs_runtime
  cd /repo/scripts/musl_derisk
  g++ -static -O2 -ffunction-sections -fdata-sections -Wl,--gc-sections \
    derisk.c -o /tmp/derisk_musl /tmp/vs/lib/libhs_runtime.a -lssl -lcrypto -lpthread
  strip /tmp/derisk_musl
  file /tmp/derisk_musl
  readelf -d /tmp/derisk_musl | grep NEEDED || echo "零 NEEDED ✓"
  nm /tmp/derisk_musl | grep -cE "_ZNSt|__cxa_throw|_Znwm" # 期望 0
  /tmp/derisk_musl
'
```

预期:`Not a valid dynamic program`(真静态)、零 NEEDED、libstdc++ 符号数 0、`derisk ok`。
