// 仅 TLS 体积测量:用 OpenSSL static 作 BoringSSL 的上界代理。
#include <stdio.h>

#include <openssl/sha.h>
#include <openssl/ssl.h>

int main(void) {
    unsigned char d[32];
    SHA256((const unsigned char*)"x", 1, d);
    SSL_CTX* c = SSL_CTX_new(TLS_method());
    if (!c) {
        fprintf(stderr, "FAIL: SSL_CTX_new\n");
        return 1;  // 真失败才非零退出
    }
    SSL_CTX_free(c);
    // 触达 d 让 SHA256 不被优化掉,但成功路径必须退出 0。原来的 `return d[0]` 会因哈希首字节
    // 非零(如输入 "x" 时为 0x2d)而误报失败,污染任何调它的 smoke test / 自动化。
    printf("tls_only ok sha256[0]=%02x\n", d[0]);
    return 0;
}
