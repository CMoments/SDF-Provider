#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>

/* SM3 上下文结构 */
typedef struct {
    EVP_MD_CTX *mdctx;
} SIMPLE_SM3_CTX;

/* 创建新的 SM3 上下文 */
static void *simple_sm3_newctx(void *provctx) {
    SIMPLE_SM3_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) return NULL;
    ctx->mdctx = EVP_MD_CTX_new();
    if (ctx->mdctx == NULL) {
        OPENSSL_free(ctx);
        return NULL;
    }
    return ctx;
}

/* 释放 SM3 上下文 */
static void simple_sm3_freectx(void *vctx) {
    SIMPLE_SM3_CTX *ctx = vctx;
    if (ctx) {
        EVP_MD_CTX_free(ctx->mdctx);
        OPENSSL_free(ctx);
    }
}

/* 初始化 SM3 */
static int simple_sm3_init(void *vctx) {
    SIMPLE_SM3_CTX *ctx = vctx;
    return EVP_DigestInit_ex(ctx->mdctx, EVP_sm3(), NULL);
}

/* 更新 SM3 */
static int simple_sm3_update(void *vctx, const unsigned char *data, size_t datalen) {
    SIMPLE_SM3_CTX *ctx = vctx;
    return EVP_DigestUpdate(ctx->mdctx, data, datalen);
}

/* 完成 SM3 */
static int simple_sm3_final(void *vctx, unsigned char *out, size_t *outlen, size_t outsize) {
    SIMPLE_SM3_CTX *ctx = vctx;
    unsigned int len;
    if (!EVP_DigestFinal_ex(ctx->mdctx, out, &len)) return 0;
    *outlen = len;
    return 1;
}

/* SM3 分发表 */
static const OSSL_DISPATCH simple_sm3_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))simple_sm3_newctx },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))simple_sm3_freectx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))simple_sm3_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))simple_sm3_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))simple_sm3_final },
    { 0, NULL }
};

/* SM3 算法定义 */
static const OSSL_ALGORITHM simple_sm3_algos[] = {
    { "SM3", "provider=simple", simple_sm3_functions, "Simple SM3 Implementation" },
    { NULL, NULL, NULL, NULL }
};

const OSSL_ALGORITHM *get_simple_sm3_algorithms(void) {
    return simple_sm3_algos;
}