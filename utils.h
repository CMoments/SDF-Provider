#ifndef SDF_DEFS_H
#define SDF_DEFS_H

#include <openssl/rsa.h>
#include "sdf_defs.h"
// 定义 RSArefPublicKey 结构
// typedef struct {
//     int bits; // 密钥的位数
//     unsigned char m[256]; // 模数 n
//     unsigned char e[4]; // 公钥指数 e
// } RSArefPublicKey;

// 函数声明
int generate_rsa_keypair_to_pem(const char *private_key_file,
                                const char *public_key_file,
                                int key_bits);
int convert_openssl_rsa_to_rsaref(RSA *rsa, RSArefPublicKey *rsa_ref);
void print_rsa_key_info(const char *filename, int is_private);
int load_rsa_public_key_from_file(const char *filename, RSArefPublicKey *rsa_ref);

#endif // SDF_DEFS_H