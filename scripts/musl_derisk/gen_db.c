// rut-MASTER 侧:用 *完整* vectorscan(带编译器)把一个小模式编译 + 序列化成
// 可移植的 DB 字节,写到 argv[1]。rut-node 永远不做这步 —— 它只反序列化。
// 链 libhs.a(full),不是 libhs_runtime.a。
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hs.h>  // 完整 compile API(本侧是 master,允许背 C++ 运行时)

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: gen_db <out.bin>\n");
        return 2;
    }
    // Target the NODE baseline, not the master's host CPU: a NULL platform makes hs_compile
    // bake the build machine's ISA into the DB, so an AVX2/AVX512 master would emit a DB older
    // x86-64-v2 nodes can't deserialize — silently breaking the master→node contract. Pin the
    // conservative baseline (no AVX2/AVX512; tune generic) so the serialized DB is portable.
    hs_platform_info_t plat;
    memset(&plat, 0, sizeof(plat));
    plat.tune = HS_TUNE_FAMILY_GENERIC;
    plat.cpu_features = 0;  // 无 AVX2/AVX512 -> SSE4.2 基线,可移植到 x86-64-v2 节点

    hs_database_t* db = NULL;
    hs_compile_error_t* err = NULL;
    if (hs_compile("foo", HS_FLAG_DOTALL, HS_MODE_BLOCK, &plat, &db, &err) != HS_SUCCESS) {
        fprintf(stderr, "FAIL: hs_compile: %s\n", err && err->message ? err->message : "?");
        hs_free_compile_error(err);
        return 1;
    }
    char* bytes = NULL;
    size_t len = 0;
    if (hs_serialize_database(db, &bytes, &len) != HS_SUCCESS) {
        fprintf(stderr, "FAIL: hs_serialize_database\n");
        return 1;
    }
    FILE* f = fopen(argv[1], "wb");
    if (!f || fwrite(bytes, 1, len, f) != len) {
        fprintf(stderr, "FAIL: write %s\n", argv[1]);
        return 1;
    }
    fclose(f);
    free(bytes);
    hs_free_database(db);
    fprintf(stderr, "gen_db: serialized %zu bytes -> %s\n", len, argv[1]);
    return 0;
}
