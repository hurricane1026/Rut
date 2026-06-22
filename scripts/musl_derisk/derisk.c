// musl-static 去风险测试:同时触达 vectorscan runtime 与 BoringSSL,
// 验证这两个库能静态链进一个零 .so 的 musl 二进制。
//
// 关键:只调用 *runtime* 侧 API(hs_deserialize/hs_scan/hs_valid_platform),
// 不碰 hs_compile —— 模拟 rut-node 只链 libhs_runtime 的场景。
#include <stdio.h>
#include <string.h>

#include <hs/hs.h>            // vectorscan runtime API
#include <openssl/sha.h>     // BoringSSL
#include <openssl/ssl.h>     // BoringSSL TLS

static int on_match(unsigned int id, unsigned long long from,
                    unsigned long long to, unsigned int flags, void* ctx) {
    (void)id; (void)from; (void)to; (void)flags;
    *(int*)ctx += 1;
    return 0;
}

int main(void) {
    // --- BoringSSL: 哈希 + TLS 上下文 (确保链到 crypto + ssl) ---
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)"rut", 3, digest);
    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    if (!ctx) { fprintf(stderr, "SSL_CTX_new failed\n"); return 1; }
    SSL_CTX_free(ctx);

    // --- vectorscan runtime: 只走 runtime 路径 ---
    // hs_valid_platform 是纯 runtime 符号 (检测当前 CPU 是否被 runtime 支持)。
    hs_error_t pv = hs_valid_platform();
    printf("hs_valid_platform=%d sha256[0]=%02x\n", (int)pv, digest[0]);

    // 触达 hs_scan/hs_alloc_scratch 的符号 (即便不真正编译 DB,也强制链进 runtime)。
    // 真正的 rut-node 路径是 hs_deserialize_database(master 下发) -> hs_scan。
    void* db_marker = (void*)&hs_deserialize_database;
    void* scan_marker = (void*)&hs_scan;
    int hits = 0;
    (void)db_marker; (void)scan_marker; (void)on_match; (void)hits;

    printf("derisk ok\n");
    return 0;
}
