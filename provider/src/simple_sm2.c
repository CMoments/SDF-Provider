#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>

/* SM2 上下文结构 */
typedef struct {
    EVP_PKEY_CTX *pkey_ctx;
} SIMPLE_SM2_CTX;

/* 创建新的 SM2 上下文 */
static void *simple_sm2_newctx(void *provctx) {
    SIMPLE_SM2_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) return NULL;
    ctx->pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
    if (ctx->pkey_ctx == NULL) {
        OPENSSL_free(ctx);
        return NULL;
    }
    return ctx;
}

/* 释放 SM2 上下文 */
static void simple_sm2_freectx(void *vctx) {
    SIMPLE_SM2_CTX *ctx = vctx;
    if (ctx) {
        EVP_PKEY_CTX_free(ctx->pkey_ctx);
        OPENSSL_free(ctx);
    }
}

/* SM2 签名 */
static int simple_sm2_sign(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize, const unsigned char *tbs, size_t tbslen) {
    SIMPLE_SM2_CTX *ctx = vctx;
    if (!EVP_PKEY_sign(ctx->pkey_ctx, sig, siglen, tbs, tbslen)) return 0;
    return 1;
}

/* SM2 分发表 */
static const OSSL_DISPATCH simple_sm2_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))simple_sm2_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))simple_sm2_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))simple_sm2_sign },
    { 0, NULL }
};

/* SM2 算法定义 */
static const OSSL_ALGORITHM simple_sm2_algos[] = {
    { "SM2", "provider=simple", simple_sm2_functions, "Simple SM2 Implementation" },
    { NULL, NULL, NULL, NULL }
};

const OSSL_ALGORITHM *get_simple_sm2_algorithms(void) {
    return simple_sm2_algos;
}