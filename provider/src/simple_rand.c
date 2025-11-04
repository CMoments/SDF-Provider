/* Simple RAND implementation for OpenSSL provider
 * 展示如何实现 OSSL_OP_RAND 操作
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

/* ========== RAND 上下文结构 ========== */
typedef struct {
    void *provctx;  /* 指向 provider 上下文 */
    int fd;         /* /dev/urandom 文件描述符 */
} SIMPLE_RAND_CTX;

/* ========== RAND 必需的函数 ========== */

/* 创建新的 RAND 上下文 */
static void *simple_rand_newctx(void *provctx, void *parent,
                                const OSSL_DISPATCH *parent_dispatch)
{
    SIMPLE_RAND_CTX *ctx = malloc(sizeof(SIMPLE_RAND_CTX));
    if (!ctx) {
        return NULL;
    }
    
    ctx->provctx = provctx;
    ctx->fd = open("/dev/urandom", O_RDONLY);
    if (ctx->fd < 0) {
        free(ctx);
        return NULL;
    }
    
    fprintf(stderr, "simple_rand: newctx created (fd=%d)\n", ctx->fd);
    return ctx;
}

/* 释放 RAND 上下文 */
static void simple_rand_freectx(void *vctx)
{
    SIMPLE_RAND_CTX *ctx = vctx;
    if (!ctx) {
        return;
    }
    
    if (ctx->fd >= 0) {
        close(ctx->fd);
    }
    fprintf(stderr, "simple_rand: freectx\n");
    free(ctx);
}

/* 初始化/实例化 RAND */
static int simple_rand_instantiate(void *vctx, unsigned int strength,
                                   int prediction_resistance,
                                   const unsigned char *pstr, size_t pstr_len,
                                   const OSSL_PARAM params[])
{
    fprintf(stderr, "simple_rand: instantiate (strength=%u)\n", strength);
    return 1; /* success */
}

/* 反初始化 RAND */
static int simple_rand_uninstantiate(void *vctx)
{
    fprintf(stderr, "simple_rand: uninstantiate\n");
    return 1;
}

/* 生成随机数 - 核心函数 */
static int simple_rand_generate(void *vctx, unsigned char *out, size_t outlen,
                                unsigned int strength,
                                int prediction_resistance,
                                const unsigned char *adin, size_t adin_len)
{
    SIMPLE_RAND_CTX *ctx = vctx;
    ssize_t bytes_read;
    
    fprintf(stderr, "==========================================\n");
    fprintf(stderr, "simple_rand: GENERATE called!\n");
    fprintf(stderr, "  Requested: %zu bytes\n", outlen);
    fprintf(stderr, "  Strength: %u\n", strength);
    fprintf(stderr, "  This is the ENTROPY SOURCE being called!\n");
    fprintf(stderr, "==========================================\n");
    
    if (!ctx || ctx->fd < 0 || !out || outlen == 0) {
        return 0;
    }
    
    /* 从 /dev/urandom 读取随机数据 */
    bytes_read = read(ctx->fd, out, outlen);
    if (bytes_read != (ssize_t)outlen) {
        fprintf(stderr, "simple_rand: generate failed (read %zd/%zu bytes)\n",
                bytes_read, outlen);
        return 0;
    }
    
    fprintf(stderr, "simple_rand: generated %zu bytes successfully\n", outlen);
    return 1; /* success */
}

/* 重新播种（可选） */
static int simple_rand_reseed(void *vctx, int prediction_resistance,
                              const unsigned char *entropy, size_t ent_len,
                              const unsigned char *adin, size_t adin_len)
{
    fprintf(stderr, "simple_rand: reseed (ignored for /dev/urandom)\n");
    return 1; /* success */
}

/* 获取参数 */
static int simple_rand_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL) {
        /* 最大请求大小：1MB */
        if (!OSSL_PARAM_set_size_t(p, 1024 * 1024)) {
            return 0;
        }
    }
    
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p != NULL) {
        /* 状态：就绪（1 = EVP_RAND_STATE_READY） */
        if (!OSSL_PARAM_set_int(p, 1)) {
            return 0;
        }
    }
    
    return 1;
}

/* 可查询的参数 */
static const OSSL_PARAM *simple_rand_gettable_ctx_params(void *vctx,
                                                          void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

/* 启用锁定（可选） */
static int simple_rand_enable_locking(void *vctx)
{
    return 1;
}

/* 锁定（可选） */
static int simple_rand_lock(void *vctx)
{
    return 1;
}

/* 解锁（可选） */
static void simple_rand_unlock(void *vctx)
{
    /* nothing */
}

/* ========== RAND 分发表 ========== */
/* 这是关键！将所有函数注册到 OpenSSL */


/*
According to core_dispatch.h

# define OSSL_FUNC_RAND_NEWCTX                        1
# define OSSL_FUNC_RAND_FREECTX                       2
# define OSSL_FUNC_RAND_INSTANTIATE                   3
# define OSSL_FUNC_RAND_UNINSTANTIATE                 4
# define OSSL_FUNC_RAND_GENERATE                      5
# define OSSL_FUNC_RAND_RESEED                        6
# define OSSL_FUNC_RAND_NONCE                         7
# define OSSL_FUNC_RAND_ENABLE_LOCKING                8
# define OSSL_FUNC_RAND_LOCK                          9
# define OSSL_FUNC_RAND_UNLOCK                       10
# define OSSL_FUNC_RAND_GETTABLE_PARAMS              11
# define OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS          12
# define OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS          13
# define OSSL_FUNC_RAND_GET_PARAMS                   14
# define OSSL_FUNC_RAND_GET_CTX_PARAMS               15
# define OSSL_FUNC_RAND_SET_CTX_PARAMS               16
# define OSSL_FUNC_RAND_VERIFY_ZEROIZATION           17
# define OSSL_FUNC_RAND_GET_SEED                     18
# define OSSL_FUNC_RAND_CLEAR_SEED                   19

*/
static const OSSL_DISPATCH simple_rand_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void))simple_rand_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void))simple_rand_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))simple_rand_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))simple_rand_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void))simple_rand_generate },
    { OSSL_FUNC_RAND_RESEED, (void (*)(void))simple_rand_reseed },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))simple_rand_get_ctx_params },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void))simple_rand_gettable_ctx_params },
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))simple_rand_enable_locking },
    { OSSL_FUNC_RAND_LOCK, (void (*)(void))simple_rand_lock },
    { OSSL_FUNC_RAND_UNLOCK, (void (*)(void))simple_rand_unlock },
    { 0, NULL }
};

/* ========== 算法定义 ========== */
/* 这个数组会被 query_operation 返回 */
static const OSSL_ALGORITHM simple_rand_algos[] = {
    { "SIMPLE-RAND", "provider=simple", simple_rand_functions, "Simple Random Generator" },
    { NULL, NULL, NULL, NULL }
};

/* 导出符号供外部使用 */
const OSSL_ALGORITHM *get_simple_rand_algorithms(void)
{
    return simple_rand_algos;
}
