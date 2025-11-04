#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h> 
#include <openssl/core_names.h> 
#include <stdio.h>
#include <string.h>

/* 定义 provider 名称 */
#define TONGSUO_PROVIDER_NAME "tongsuo-provider"


extern const OSSL_ALGORITHM *get_simple_rand_algorithms(void);
extern const OSSL_ALGORITHM *get_simple_sm4_ciphers(void);

/* 算法查询函数 */
static const OSSL_ALGORITHM *tongsuo_query(
    void *provctx,
    int operation_id,
    int *no_cache)
{
    *no_cache = 0;
    
    switch (operation_id) {
        // 这里还没有使用providctx参数，最小化的概念实现
  // 这里结束代码块
        case OSSL_OP_RAND:{
            const OSSL_ALGORITHM *rand_algs = get_simple_rand_algorithms();
            return rand_algs;
        }
        case OSSL_OP_CIPHER: { 
            const OSSL_ALGORITHM *cipher_algs = get_simple_sm4_ciphers();
            printf(" - SO - 调用了查询算法，返回算法相关的所有函数\n"); 
            return cipher_algs;
        }
        // case OSSL_OP_DIGEST:
        //     return get_simple_sm3_algorithms();
        // case OSSL_OP_SIGNATURE:
        //     return get_simple_sm2_algorithms();
        default:
            return NULL;
    }
}

/* Provider 的 teardown 函数 */
static void tongsuo_teardown(void *provctx)
{
    // 清理资源
}

/* Provider 的核心函数表 */
static const OSSL_DISPATCH tongsuo_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))tongsuo_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))tongsuo_query },
    { 0, NULL }
};

/* Provider 的初始化函数 */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                      const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out,
                      void **provctx)
{
    *out = tongsuo_dispatch_table;
    *provctx = (void *)handle;
    
    printf("Tongsuo Provider initialized successfully\n");
    return 1;
}