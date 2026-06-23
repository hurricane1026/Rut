// rut-NODE 侧的 musl-static 去风险:只链 vectorscan *runtime*(libhs_runtime.a,无编译器)
// + BoringSSL,验证两者能静态链进一个零 .so 的 musl 二进制,并且**真正跑通** rut-node 的
// 路径:反序列化 master 下发的 DB -> 分配 scratch -> hs_scan 出命中。
//
// DB 由 gen_db(master 侧,完整 libhs)预先编译+序列化,经 argv[1] 传入 —— 精确镜像
// rut-master(编译)/ rut-node(只反序列化+扫描)的拆分。每步 fail-hard:一次成功运行
// 才是真的成功,而不是 -O2 把检查优化掉后照样打印 "derisk ok"。
//
// 头走 vendored(-I third_party/vectorscan/src + third_party/boringssl/include),不依赖系统包。
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hs_common.h>   // hs_valid_platform / hs_deserialize_database / hs_free_database
#include <hs_runtime.h>  // hs_scan / hs_alloc_scratch / hs_free_scratch / hs_scratch_t
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

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: derisk <db.bin>  (master-serialized DB from gen_db)\n");
        return 2;
    }

    // --- BoringSSL: 哈希 + TLS 上下文 (确保链到 crypto + ssl) ---
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)"rut", 3, digest);
    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    if (!ctx) {
        fprintf(stderr, "FAIL: SSL_CTX_new (BoringSSL TLS)\n");
        return 1;
    }
    SSL_CTX_free(ctx);

    // --- vectorscan runtime: 当前 CPU 必须被这份 (FAT_RUNTIME=OFF) runtime 支持 ---
    if (hs_valid_platform() != HS_SUCCESS) {
        fprintf(stderr, "FAIL: hs_valid_platform (runtime not usable on this CPU)\n");
        return 1;
    }

    // --- 读 master 下发的序列化 DB ---
    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "FAIL: open %s\n", argv[1]);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) {
        fprintf(stderr, "FAIL: empty DB %s\n", argv[1]);
        return 1;
    }
    char* buf = (char*)malloc((size_t)sz);
    if (!buf || fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        fprintf(stderr, "FAIL: read DB\n");
        return 1;
    }
    fclose(f);

    // --- rut-node 真实路径:反序列化 -> 分配 scratch -> 扫描 ---
    hs_database_t* db = NULL;
    if (hs_deserialize_database(buf, (size_t)sz, &db) != HS_SUCCESS) {
        fprintf(stderr, "FAIL: hs_deserialize_database\n");
        return 1;
    }
    hs_scratch_t* scratch = NULL;
    if (hs_alloc_scratch(db, &scratch) != HS_SUCCESS) {
        fprintf(stderr, "FAIL: hs_alloc_scratch\n");
        return 1;
    }
    int hits = 0;
    const char* data = "xx foo yy";  // 含模式 "foo"
    if (hs_scan(db, data, (unsigned int)strlen(data), 0, scratch, on_match, &hits) != HS_SUCCESS) {
        fprintf(stderr, "FAIL: hs_scan\n");
        return 1;
    }
    if (hits < 1) {
        fprintf(stderr, "FAIL: expected >=1 match for 'foo', got %d\n", hits);
        return 1;
    }

    hs_free_scratch(scratch);
    hs_free_database(db);
    free(buf);
    printf("derisk ok: valid_platform=HS_SUCCESS scan_hits=%d sha256[0]=%02x\n", hits, digest[0]);
    return 0;
}
