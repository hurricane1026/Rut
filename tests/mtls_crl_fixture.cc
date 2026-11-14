// Test-only certificates and CRLs generated with the project's pinned OpenSSL.
#include "rut/runtime/tls.h"

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

namespace {
FILE* output(const char* directory, const char* name) {
    char path[1024];
    const int kSize = snprintf(path, sizeof(path), "%s/%s", directory, name);
    return kSize > 0 && static_cast<unsigned>(kSize) < sizeof(path) ? fopen(path, "w") : nullptr;
}
bool client(X509* issuer, EVP_PKEY* key, long serial, const char* directory, const char* file) {
    X509* cert = X509_new();
    bool ok = cert && X509_set_version(cert, 2) == 1 &&
              ASN1_INTEGER_set(X509_get_serialNumber(cert), serial) == 1 &&
              X509_set_issuer_name(cert, X509_get_subject_name(issuer)) == 1 &&
              X509_set_pubkey(cert, key) == 1 &&
              X509_NAME_add_entry_by_txt(X509_get_subject_name(cert),
                                         "CN",
                                         MBSTRING_ASC,
                                         reinterpret_cast<const unsigned char*>(file),
                                         -1,
                                         -1,
                                         0) == 1 &&
              X509_gmtime_adj(X509_getm_notBefore(cert), -60) &&
              X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
    X509_EXTENSION* usage = X509V3_EXT_conf_nid(
        nullptr, nullptr, NID_key_usage, const_cast<char*>("critical,digitalSignature"));
    X509_EXTENSION* purpose =
        X509V3_EXT_conf_nid(nullptr, nullptr, NID_ext_key_usage, const_cast<char*>("clientAuth"));
    ok = ok && usage && purpose && X509_add_ext(cert, usage, -1) == 1 &&
         X509_add_ext(cert, purpose, -1) == 1 && X509_sign(cert, key, EVP_sha256()) > 0;
    FILE* out = output(directory, file);
    ok = ok && out && PEM_write_X509(out, cert) == 1;
    if (out) fclose(out);
    X509_EXTENSION_free(usage);
    X509_EXTENSION_free(purpose);
    X509_free(cert);
    return ok;
}
bool crl(X509* issuer,
         EVP_PKEY* key,
         const char* directory,
         const char* file,
         bool revoked = true,
         long last_offset = -60,
         long next_offset = 3600,
         bool next_present = true,
         bool wrong_issuer = false,
         bool delta = false,
         bool partitioned = false) {
    X509_CRL* list = X509_CRL_new();
    ASN1_TIME* last = ASN1_TIME_adj(nullptr, time(nullptr), 0, last_offset);
    ASN1_TIME* next = ASN1_TIME_adj(nullptr, time(nullptr), 0, next_offset);
    X509_NAME* name = X509_NAME_dup(X509_get_subject_name(issuer));
    if (wrong_issuer && name)
        X509_NAME_add_entry_by_txt(name,
                                   "CN",
                                   MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>("wrong-issuer"),
                                   -1,
                                   -1,
                                   0);
    bool ok = list && last && next && name && X509_CRL_set_version(list, 1) == 1 &&
              X509_CRL_set_issuer_name(list, name) == 1 &&
              X509_CRL_set1_lastUpdate(list, last) == 1 &&
              (!next_present || X509_CRL_set1_nextUpdate(list, next) == 1);
    if (ok && revoked) {
        X509_REVOKED* entry = X509_REVOKED_new();
        ASN1_INTEGER* serial = ASN1_INTEGER_new();
        ok = entry && serial && ASN1_INTEGER_set(serial, 1) == 1 &&
             X509_REVOKED_set_serialNumber(entry, serial) == 1 &&
             X509_REVOKED_set_revocationDate(entry, last) == 1 &&
             X509_CRL_add0_revoked(list, entry) == 1;
        if (!ok) X509_REVOKED_free(entry);
        ASN1_INTEGER_free(serial);
    }
    if (ok && delta) {
        ASN1_INTEGER* number = ASN1_INTEGER_new();
        ok = number && ASN1_INTEGER_set(number, 1) == 1 &&
             X509_CRL_add1_ext_i2d(list, NID_delta_crl, number, 1, 0) == 1;
        ASN1_INTEGER_free(number);
    }
    if (ok && partitioned) {
        ISSUING_DIST_POINT* distribution = ISSUING_DIST_POINT_new();
        if (distribution) distribution->indirectCRL = 1;
        ok = distribution &&
             X509_CRL_add1_ext_i2d(list, NID_issuing_distribution_point, distribution, 1, 0) == 1;
        ISSUING_DIST_POINT_free(distribution);
    }
    ok = ok && X509_CRL_sort(list) == 1 && X509_CRL_sign(list, key, EVP_sha256()) > 0;
    FILE* out = output(directory, file);
    ok = ok && out && PEM_write_X509_CRL(out, list) == 1;
    if (out) fclose(out);
    X509_NAME_free(name);
    ASN1_TIME_free(last);
    ASN1_TIME_free(next);
    X509_CRL_free(list);
    return ok;
}
bool verify_leaf(rut::TlsServerContext* ctx,
                 const char* directory,
                 const char* name,
                 bool expected) {
    char path[1024];
    if (snprintf(path, sizeof(path), "%s/%s", directory, name) >= static_cast<int>(sizeof(path)))
        return false;
    FILE* input = fopen(path, "r");
    X509* cert = input ? PEM_read_X509(input, nullptr, nullptr, nullptr) : nullptr;
    if (input) fclose(input);
    X509_STORE_CTX* verification = X509_STORE_CTX_new();
    bool ok = cert && verification &&
              X509_STORE_CTX_init(
                  verification, SSL_CTX_get_cert_store(ctx->ssl_ctx), cert, nullptr) == 1 &&
              X509_STORE_CTX_set_purpose(verification, X509_PURPOSE_SSL_CLIENT) == 1;
    if (ok) ok = (X509_verify_cert(verification) == 1) == expected;
    X509_STORE_CTX_free(verification);
    X509_free(cert);
    return ok;
}
int verify_contexts(const char* testdata, const char* fixtures) {
    char certificate[1024], key[1024], path[1024];
    if (snprintf(certificate, sizeof(certificate), "%s/localhost_cert.pem", testdata) >=
            static_cast<int>(sizeof(certificate)) ||
        snprintf(key, sizeof(key), "%s/localhost_key.pem", testdata) >=
            static_cast<int>(sizeof(key)))
        return 1;
    struct Case {
        const char* name;
        bool creates;
        bool first;
        bool second;
    };
    const Case kCases[] = {{nullptr, true, true, true},
                           {"clear.pem", true, true, true},
                           {"revoked.pem", true, false, true},
                           {"bad-signature.pem", true, false, false},
                           {"wrong-issuer.pem", true, false, false},
                           {"expired.pem", false, false, false},
                           {"future.pem", false, false, false},
                           {"no-next.pem", false, false, false},
                           {"delta.pem", false, false, false},
                           {"indirect.pem", false, false, false}};
    for (const auto& item : kCases) {
        if (item.name && snprintf(path, sizeof(path), "%s/%s", fixtures, item.name) >=
                             static_cast<int>(sizeof(path)))
            return 1;
        auto created = rut::create_tls_server_context(
            certificate, key, false, certificate, item.name ? path : nullptr);
        if (created.has_value() != item.creates) {
            if (created) rut::destroy_tls_server_context(created.value());
            return 1;
        }
        if (!created) continue;
        auto* ctx = created.value();
        const bool kOk = SSL_CTX_get_session_cache_mode(ctx->ssl_ctx) == SSL_SESS_CACHE_OFF &&
                         SSL_CTX_get_num_tickets(ctx->ssl_ctx) == 0 &&
                         (SSL_CTX_get_options(ctx->ssl_ctx) & SSL_OP_NO_TICKET) != 0 &&
                         verify_leaf(ctx, fixtures, "first.pem", item.first) &&
                         verify_leaf(ctx, fixtures, "second.pem", item.second);
        rut::destroy_tls_server_context(ctx);
        if (!kOk) return 1;
    }
    auto unpaired = rut::create_tls_server_context(certificate, key, false, nullptr, path);
    if (unpaired) {
        rut::destroy_tls_server_context(unpaired.value());
        return 1;
    }
    return 0;
}
}  // namespace
int main(int argc, char** argv) {
    if (argc != 3 && argc != 4) return 2;
    if (argc == 4 && strcmp(argv[3], "--verify") == 0) return verify_contexts(argv[1], argv[2]);
    char path[1024];
    if (snprintf(path, sizeof(path), "%s/localhost_cert.pem", argv[1]) >=
        static_cast<int>(sizeof(path)))
        return 2;
    FILE* in = fopen(path, "r");
    X509* issuer = in ? PEM_read_X509(in, nullptr, nullptr, nullptr) : nullptr;
    if (in) fclose(in);
    if (snprintf(path, sizeof(path), "%s/localhost_key.pem", argv[1]) >=
        static_cast<int>(sizeof(path))) {
        X509_free(issuer);
        return 2;
    }
    in = fopen(path, "r");
    EVP_PKEY* key = in ? PEM_read_PrivateKey(in, nullptr, nullptr, nullptr) : nullptr;
    if (in) fclose(in);
    bool ok = issuer && key;
    if (argc == 4) {
        const time_t kDeadline = time(nullptr) + 30;
        ok = ok && strcmp(argv[3], "--short") == 0 &&
             crl(issuer, key, argv[2], "short.pem", false, -60, 30);
        if (ok) printf("%lld\n", static_cast<long long>(kDeadline));
    } else if (ok) {
        EVP_PKEY* other = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1");
        ok = other && client(issuer, key, 1, argv[2], "first.pem") &&
             client(issuer, key, 2, argv[2], "second.pem") &&
             crl(issuer, key, argv[2], "revoked.pem") &&
             crl(issuer, key, argv[2], "clear.pem", false) &&
             crl(issuer, other, argv[2], "bad-signature.pem") &&
             crl(issuer, key, argv[2], "wrong-issuer.pem", true, -60, 3600, true, true) &&
             crl(issuer, key, argv[2], "expired.pem", true, -120, -60) &&
             crl(issuer, key, argv[2], "future.pem", true, 3600, 7200) &&
             crl(issuer, key, argv[2], "no-next.pem", true, -60, 3600, false) &&
             crl(issuer, key, argv[2], "delta.pem", true, -60, 3600, true, false, true) &&
             crl(issuer, key, argv[2], "indirect.pem", true, -60, 3600, true, false, false, true);
        EVP_PKEY_free(other);
    }
    EVP_PKEY_free(key);
    X509_free(issuer);
    return ok ? 0 : 1;
}
