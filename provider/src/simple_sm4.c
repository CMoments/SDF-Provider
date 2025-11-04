/* Simple RAND implementation for OpenSSL provider
 * 展示如何实现 OSSL_OP_sm4 操作
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>

/* SM4 ECB 上下文结构 */
typedef struct {
    unsigned char key[16];  // SM4 key is 128 bits
    int enc;                // 1 for encrypt, 0 for decrypt
} SM4_ECB_CTX;


/* 示例算法实现 - SM4 ECB */
static OSSL_FUNC_cipher_encrypt_init_fn sm4_ecb_encrypt_init;
static OSSL_FUNC_cipher_decrypt_init_fn sm4_ecb_decrypt_init;
static OSSL_FUNC_cipher_update_fn sm4_ecb_update;
static OSSL_FUNC_cipher_final_fn sm4_ecb_final;
static OSSL_FUNC_cipher_freectx_fn sm4_ecb_freectx;
static OSSL_FUNC_cipher_dupctx_fn sm4_ecb_dupctx;
static OSSL_FUNC_cipher_get_ctx_params_fn sm4_ecb_get_ctx_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn sm4_ecb_gettable_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn sm4_ecb_set_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn sm4_ecb_settable_ctx_params;
static OSSL_FUNC_cipher_newctx_fn sm4_ecb_newctx;


/* 添加 SM4 ECB 的常量定义 */
static const OSSL_PARAM sm4_ecb_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM sm4_ecb_known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_END
};


/* 创建新的 SM4 ECB 上下文 */
static void *sm4_ecb_newctx(void *provctx)
{
    printf(" - SO - 执行创建密钥上下文\n"); 
    SM4_ECB_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    return ctx;
}

/* 初始化加密 */
static int sm4_ecb_encrypt_init(void *vctx, const unsigned char *key,
                               size_t keylen, const unsigned char *iv,
                               size_t ivlen, const OSSL_PARAM params[])
{
    printf(" - SO - 执行初始话加密\n"); 
    SM4_ECB_CTX *ctx = vctx;
    
    if (keylen != 16)  // SM4 key must be 128 bits
        return 0;
    
    memcpy(ctx->key, key, keylen);
    ctx->enc = 1;
    
    return 1;
}

/* 初始化解密 */
static int sm4_ecb_decrypt_init(void *vctx, const unsigned char *key,
                               size_t keylen, const unsigned char *iv,
                               size_t ivlen, const OSSL_PARAM params[])
{
    SM4_ECB_CTX *ctx = vctx;
    
    if (keylen != 16)  // SM4 key must be 128 bits
        return 0;
    
    memcpy(ctx->key, key, keylen);
    ctx->enc = 0;
    
    return 1;
}

/* 更新操作 */
static int sm4_ecb_update(void *vctx, unsigned char *out, size_t *outl,
                         size_t outsize, const unsigned char *in, size_t inl)
{
    printf(" - SO - 执行初始话加密\n"); 
    SM4_ECB_CTX *ctx = vctx;
    
    // 这里应该是实际的 SM4 ECB 加密/解密实现
    // 为了示例，我们只是简单地将输入复制到输出
    // 实际实现应该使用 Tongsuo/OpenSSL 的 SM4 实现
    
    if (outsize < inl)
        return 0;
    
    memcpy(out, in, inl);
    *outl = inl;
    
    return 1;
}

/* 最终操作 */
static int sm4_ecb_final(void *vctx, unsigned char *out, size_t *outl,
                        size_t outsize)
{
    printf(" - SO - 完成加密，返回加密数据 0\n"); 
    *outl = 0;    
    return 1;
}

/* 释放上下文 */
static void sm4_ecb_freectx(void *vctx)
{
    SM4_ECB_CTX *ctx = vctx;
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

/* 复制上下文 */
static void *sm4_ecb_dupctx(void *vctx)
{
    SM4_ECB_CTX *ctx = vctx;
    SM4_ECB_CTX *newctx = sm4_ecb_newctx(NULL);
    
    if (newctx == NULL)
        return NULL;
    
    memcpy(newctx, ctx, sizeof(*ctx));
    return newctx;
}

/* 获取上下文参数 */
/* 更新获取上下文参数函数 */
static int sm4_ecb_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    SM4_ECB_CTX *ctx = vctx;
    OSSL_PARAM *p;
    
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN)) != NULL)
        if (!OSSL_PARAM_set_size_t(p, 0))  // ECB mode doesn't use IV
            return 0;
    
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING)) != NULL)
        if (!OSSL_PARAM_set_uint(p, 1))    // Enable padding by default
            return 0;
    
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) != NULL)
        if (!OSSL_PARAM_set_size_t(p, 16)) // SM4 key length is 16 bytes
            return 0;
    
    return 1;
}

/* 获取可设置的上下文参数 */
static const OSSL_PARAM *sm4_ecb_gettable_ctx_params(void *vctx, void *provctx)
{
    return sm4_ecb_known_gettable_params;
}

/* 设置上下文参数 */
static int sm4_ecb_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    SM4_ECB_CTX *ctx = vctx;
    const OSSL_PARAM *p;
    
    if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN)) != NULL) {
        size_t keylen;
        
        if (!OSSL_PARAM_get_size_t(p, &keylen))
            return 0;
        if (keylen != 16)  // SM4 key must be 128 bits
            return 0;
    }
    
    return 1;
}

/* 获取可设置的上下文参数 */
static const OSSL_PARAM *sm4_ecb_settable_ctx_params(void *vctx, void *provctx)
{
    return sm4_ecb_known_settable_ctx_params;
}

static int sm4_ecb_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) != NULL)
    {
        printf(" - SO - 查询 Key_leng\n");
        if (!OSSL_PARAM_set_size_t(p, 16))
            return 0;
    }   
    
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN)) != NULL)
    {
        printf(" - SO - 查询 iv_len\n");
        if (!OSSL_PARAM_set_size_t(p, 0))  // ECB doesn't use IV
            return 0;
    }
    
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE)) != NULL)
    {
        printf(" - SO - 查询 Block_size\n");
        if (!OSSL_PARAM_set_size_t(p, 16)) // SM4 block size is 16 bytes
            return 0;
    }
    
    return 1;
}

static const OSSL_PARAM *sm4_ecb_gettable_params(void *provctx)
{
    return sm4_ecb_known_gettable_params;
}

/* SM4 ECB 算法定义 */
static const OSSL_DISPATCH sm4_ecb_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))sm4_ecb_newctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))sm4_ecb_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))sm4_ecb_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))sm4_ecb_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))sm4_ecb_final },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))sm4_ecb_freectx },
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))sm4_ecb_dupctx },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))sm4_ecb_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))sm4_ecb_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))sm4_ecb_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))sm4_ecb_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))sm4_ecb_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))sm4_ecb_settable_ctx_params },
    { 0, NULL }
};





// static const OSSL_DISPATCH sm4_cbc_functions[] = {
//     { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))sm4_cbc_newctx },
//     { 0, NULL }
// };
typedef struct {
    unsigned char key[16];  // SM4 key is 128 bits
    int enc;                // 1 for encrypt, 0 for decrypt
} SM4_CBC_CTX;

static void *sm4_cbc_newctx(void *provctx)
{
    printf(" - SO - 执行创建密钥上下文\n"); 
    SM4_CBC_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    return ctx;
}
static const OSSL_ALGORITHM cipher_algs[] = {
    { "SM4-ECB", "provider=tongsuo-provider", sm4_ecb_functions },
    // { "SM4-CBC", "provider=tongsuo-provider", sm4_cbc_functions },
    { NULL, NULL, NULL }
};
const OSSL_ALGORITHM *get_simple_sm4_ciphers(void)
{
    return cipher_algs;
}