// 仅 TLS 体积测量:用 OpenSSL static 作 BoringSSL 的上界代理。
#include <openssl/ssl.h>
#include <openssl/sha.h>
int main(void) {
    unsigned char d[32];
    SHA256((const unsigned char*)"x", 1, d);
    SSL_CTX* c = SSL_CTX_new(TLS_method());
    if (c) SSL_CTX_free(c);
    return d[0];
}
