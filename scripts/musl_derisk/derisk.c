// musl-static 去风险测试:同时触达 vectorscan *runtime* 与 BoringSSL,
// 验证这两个库能静态链进一个零 .so 的 musl 二进制。
//
// 关键:只调用 *runtime* 侧 API(hs_valid_platform/hs_deserialize/hs_scan),
// 不碰 hs_compile —— 模拟 rut-node 只链 libhs_runtime 的场景。用 *vendored*
// 头(third_party/vectorscan/src + third_party/boringssl/include),不依赖系统包。
//
// 每个被验证的步骤都 FAIL-HARD(非零退出):一次成功的运行才是真的成功,
// 而不是 -O2 把检查优化掉后照样打印 "derisk ok"。
#include <stdio.h>
#include <string.h>

#include <hs_common.h>   // vectorscan runtime: hs_valid_platform / hs_deserialize_database
#include <hs_runtime.h>  // vectorscan runtime: hs_scan / hs_scratch
#include <openssl/sha.h>  // BoringSSL
#include <openssl/ssl.h>  // BoringSSL TLS

static int on_match(unsigned int id, unsigned long long from, unsigned long long to,
                    unsigned int flags, void* ctx) {
    (void)id;
    (void)from;
    (void)to;
    (void)flags;
    *(int*)ctx += 1;
    return 0;
}

int main(void) {
    // --- BoringSSL: 哈希 + TLS 上下文 (确保链到 crypto + ssl) ---
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)"rut", 3, digest);
    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    if (!ctx) {
        fprintf(stderr, "FAIL: SSL_CTX_new (BoringSSL TLS)\n");
        return 1;
    }
    SSL_CTX_free(ctx);

    // --- vectorscan runtime: 验证当前 CPU 被这份 (FAT_RUNTIME=OFF) runtime 支持。
    //     只有 HS_SUCCESS 才算可用;否则 rut-node 在此 CPU 上跑不了 —— 必须失败,
    //     不能只打印结果照样退出 0。 ---
    hs_error_t pv = hs_valid_platform();
    if (pv != HS_SUCCESS) {
        fprintf(stderr, "FAIL: hs_valid_platform=%d (runtime not usable on this CPU)\n", (int)pv);
        return 1;
    }

    // --- 真正触达 rut-node 的 runtime 路径符号:hs_deserialize_database -> hs_scan。
    //     用非法输入调用,既强制把这两个符号引用进二进制(缺失则 *链接* 失败,而不是
    //     -O2 把 (void)&fn 的死代码消掉后照样链上),又验证它们能执行并返回文档化的
    //     HS_INVALID 而不是崩溃/缺失。 ---
    hs_database_t* db = NULL;
    unsigned char junk[16] = {0};
    hs_error_t de = hs_deserialize_database((const char*)junk, sizeof(junk), &db);
    if (de != HS_INVALID) {  // 坏 magic 的反序列化必须被拒
        fprintf(stderr, "FAIL: hs_deserialize_database=%d (expected HS_INVALID=%d)\n", (int)de,
                (int)HS_INVALID);
        return 1;
    }
    int hits = 0;
    hs_error_t sc = hs_scan(NULL, "x", 1, 0, NULL, on_match, &hits);  // NULL db -> 参数校验 HS_INVALID
    if (sc != HS_INVALID) {
        fprintf(stderr, "FAIL: hs_scan=%d (expected HS_INVALID=%d)\n", (int)sc, (int)HS_INVALID);
        return 1;
    }

    printf("derisk ok: valid_platform=HS_SUCCESS deserialize=HS_INVALID scan=HS_INVALID "
           "sha256[0]=%02x\n",
           digest[0]);
    return 0;
}
