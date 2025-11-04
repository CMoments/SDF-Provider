#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>

int main()
{
    OSSL_PROVIDER *prov = NULL;
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char iv[16] = {0};
    unsigned char in[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char out[32];
    int outl, tmpl;
    
    /* 设置模块路径 */
    // 如果 provider 不在默认路径，需要设置 OPENSSL_MODULES 环境变量
    // 或者在代码中设置
    // putenv("OPENSSL_MODULES=.");
    
    /* 加载默认 provider */
    OSSL_PROVIDER_load(NULL, "default");
    
    /* 加载我们的 Tongsuo provider */
    prov = OSSL_PROVIDER_load(NULL, "libtongsuo_provider");
    if (prov == NULL) {
        fprintf(stderr, "Failed to load Tongsuo provider\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    
    /* 获取 SM4-ECB 密码 */
    printf("TEST - 开始查找算法\n");
    // cipher = EVP_CIPHER_fetch(NULL, "SM4-ECB", "provider=tongsuo-provider");
    cipher = EVP_CIPHER_fetch(NULL, "SM4-ECB", "provider=tongsuo-provider");
    if (cipher == NULL) {
        fprintf(stderr, "Failed to fetch SM4-ECB cipher\n");
        ERR_print_errors_fp(stderr);
        OSSL_PROVIDER_unload(prov);
        return 1;
    }
    
    // printf("Successfully fetched SM4-ECB cipher\n");



    printf("TEST - 打印 Block Size\n");
    printf("Block size: %d\n", EVP_CIPHER_get_block_size(cipher));  // 关联 OSSL_FUNC_CIPHER_GET_PARAMS 标识
    printf("TEST - 打印 Key_length\n");
    printf("Key length: %d\n", EVP_CIPHER_get_key_length(cipher));
    printf("TEST - 打印 iv_length\n");
    printf("IV length: %d\n", EVP_CIPHER_get_iv_length(cipher));
    
 

    /* 创建加密上下文 */
    printf("TEST - 创建加密上下文\n");
    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        fprintf(stderr, "Failed to create cipher context\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_free(cipher);
        OSSL_PROVIDER_unload(prov);
        return 1;
    }

    // 默认是启用padding的，这里关闭padding以便测试
    EVP_CIPHER_CTX_set_padding(ctx, 0);



    /* 初始化加密操作 */
    printf("TEST - 初始化加密操作\n");
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        fprintf(stderr, "Failed to initialize encryption\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(cipher);
        OSSL_PROVIDER_unload(prov);
        return 1;
    }
    
    /* 执行加密 */
    printf("TEST - 执行加密\n");
    if (EVP_EncryptUpdate(ctx, out, &outl, in, sizeof(in)) != 1) {
        fprintf(stderr, "Failed to encrypt data\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(cipher);
        OSSL_PROVIDER_unload(prov);
        return 1;
    }
    
    /* 完成加密 */
    printf("TEST - 完成加密\n");
    if (EVP_EncryptFinal_ex(ctx, out + outl, &tmpl) != 1) {
        fprintf(stderr, "Failed to finalize encryption\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(cipher);
        OSSL_PROVIDER_unload(prov);
        return 1;
    }
    outl += tmpl;
    
    printf("Encryption successful. Output length: %d\n", outl);
    
    /* 打印加密结果 */
    printf("Ciphertext: ");
    for (int i = 0; i < outl; i++) {
        printf("%02x", out[i]);
    }
    printf("\n");
    
    /* 清理 */
    printf("TEST - 上下文清理\n");
    EVP_CIPHER_CTX_free(ctx);
    printf("TEST - 算法模块清理\n");
    EVP_CIPHER_free(cipher);
    printf("TEST - provider清理\n");
    OSSL_PROVIDER_unload(prov);
    
    return 0;
}