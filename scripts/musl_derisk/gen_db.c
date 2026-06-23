// rut-MASTER 侧:用 *完整* vectorscan(带编译器)把一个小模式编译 + 序列化成
// 可移植的 DB 字节,写到 argv[1]。rut-node 永远不做这步 —— 它只反序列化。
// 链 libhs.a(full),不是 libhs_runtime.a。
#include <stdio.h>
#include <stdlib.h>

#include <hs.h>  // 完整 compile API(本侧是 master,允许背 C++ 运行时)

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: gen_db <out.bin>\n");
        return 2;
    }
    hs_database_t* db = NULL;
    hs_compile_error_t* err = NULL;
    if (hs_compile("foo", HS_FLAG_DOTALL, HS_MODE_BLOCK, NULL, &db, &err) != HS_SUCCESS) {
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
