#include<openssl/rsa.h>
#include<openssl/pem.h>
#include"sdf_defs.h"
#include<string.h>
#include<stdlib.h>
/*
    The utils for testcases.c
*/
#define DEBUG 
#ifdef DEBUG
    #define debug_printf(...) printf(__VA_ARGS__)
#else
    #define debug_printf(...)
#endif
void print_rsa_ref_public_key( RSArefPublicKey *rsa_ref) {
    if (!rsa_ref) {
        printf("RSArefPublicKey is NULL\n");
        return;
    }

    printf("RSArefPublicKey Information:\n");
    printf("  Bits: %u\n", rsa_ref->bits);

    // 打印模数 m
    int mark = 1;
    printf("  Modulus (m): ");
    for (int i = 0; i < RSAref_MAX_LEN ; i++) {
        if(rsa_ref->m[i] == 0 && mark)continue;
        else{
            mark = 0;
            printf("%02X", rsa_ref->m[i]);
        }
    }
    printf("\n");

    // 打印公钥指数 e
    printf("  Public Exponent (e): ");
    mark = 1;
    for (int i = 0; i < RSAref_MAX_LEN; i++) {
        if( rsa_ref->e[i] == 0 && mark)continue;
        else{
            mark = 0;
            printf("%02X", rsa_ref->e[i]);  
        }
    }
    printf("\n");
}
int generate_rsa_keypair_to_pem(const char *private_key_file,
                                const char *public_key_file,
                                int key_bits){
    RSA *rsa = NULL;
    FILE *fp_private = NULL;
    FILE *fp_public = NULL;
    int ret = -1;

    rsa = RSA_new();
    if (! rsa ){
        debug_printf("Error creating RSA structure\n");
        goto cleanup;
    }
    BIGNUM *bne = BN_new();
    if (!bne){
        debug_printf("Error creating BIGNUM\n");
        printf("Error creating BIGNUM\n");
        goto cleanup;
    }
    if (BN_set_word(bne, RSA_F4) != 1){
        debug_printf("Error setting RSA exponent\n");
        goto cleanup;
    }

    if (RSA_generate_key_ex(rsa,key_bits,bne, NULL) != 1){
        debug_printf("Error generating RSA key pair\n");
        goto cleanup;
    }

    fp_private = fopen(private_key_file,"w");
    if(!fp_private){
        debug_printf("Error opening private key file: %s\n", private_key_file);
        goto cleanup;
    }
    if (!PEM_write_RSAPrivateKey(fp_private,rsa,NULL,NULL,0,NULL,NULL)){
        debug_printf("Error writing private key\n");
        goto cleanup;
    }
    fclose(fp_private);
    fp_private = NULL;

    fp_public = fopen(public_key_file,"w");
    if(!fp_public){
        debug_printf("Error opening public key file: %s\n", public_key_file);
        goto cleanup;
    }
    if (!PEM_write_RSA_PUBKEY(fp_public, rsa)) {
        printf("Error writing public key\n");
        goto cleanup;
    }
    fclose(fp_public);
    fp_public = NULL;

    printf("RSA key pair generated successfully:\n");
    printf("  Private key: %s\n", private_key_file);
    printf("  Public key:  %s\n", public_key_file);
    printf("  Key size:    %d bits\n", key_bits);
    
    ret = 0;

cleanup:
    if (fp_private)fclose(fp_private);
    if (fp_public)fclose(fp_public);
    if (rsa)RSA_free(rsa);
    if (bne)BN_free(bne);
    return ret;
}
int convert_openssl_rsa_to_rsaref(RSA *rsa, RSArefPublicKey *rsa_ref) {
    if (!rsa || !rsa_ref) {
        debug_printf("Invalid input parameters\n");
        return -1;
    }

    const BIGNUM *n, *e;
    RSA_get0_key(rsa, &n, &e, NULL);

    // 设置比特长度
    rsa_ref->bits = RSA_size(rsa) * 8;
    debug_printf("RSA bits: %u\n", rsa_ref->bits);

    // 将模数 n 转换为字节数组
    int n_len = BN_num_bytes(n);
    if (n_len > sizeof(rsa_ref->m)) {
        debug_printf("Modulus n is too large\n");
        return -1;
    }
    debug_printf("Modulus n length: %d bytes\n", n_len);

    // 确保数组清零
    memset(rsa_ref->m, 0, sizeof(rsa_ref->m));
    BN_bn2bin(n, rsa_ref->m + (sizeof(rsa_ref->m) - n_len)); // 大端格式
    debug_printf("Modulus n: ");
    for (int i = 0; i < n_len; i++) {
        debug_printf("%02X", rsa_ref->m[sizeof(rsa_ref->m) - n_len + i]);
    }
    debug_printf("\n");

    // 将指数 e 转换为字节数组
    int e_len = BN_num_bytes(e);
    if (e_len > sizeof(rsa_ref->e)) {
        debug_printf("Exponent e is too large\n");
        return -1;
    }
    debug_printf("Exponent e length: %d bytes\n", e_len);

    // 确保数组清零
    memset(rsa_ref->e, 0, sizeof(rsa_ref->e));
    BN_bn2bin(e, rsa_ref->e + (sizeof(rsa_ref->e) - e_len)); // 大端格式
    debug_printf("Exponent e: ");
    for (int i = 0; i < e_len; i++) {
        debug_printf("%02X", rsa_ref->e[sizeof(rsa_ref->e) - e_len + i]);
    }
    debug_printf("\n");

    return 0;
}
// 从PEM文件加载RSA公钥并转换为RSArefPublicKey格式
int load_rsa_public_key_from_file(const char *filename, RSArefPublicKey *rsa_ref) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return -1;
    
    RSA *rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!rsa) {
        debug_printf("Error reading RSA_public_key\n");
    }
    
    int ret = convert_openssl_rsa_to_rsaref(rsa, rsa_ref);
    debug_printf("ret: %d\n",ret);
    // printf("ret\n\n");
    RSA_free(rsa);
    return ret;
}
int main(){

    // generate_rsa_keypair_to_pem("RSA_privatekey.pem","RSA_publickey.pem",1024);
    // print_rsa_key_info("RSA_privatekey.pem",1);
    // RSArefPublicKey testrsa;
    // memset(&testrsa, 0, sizeof(RSArefPublicKey));
    // load_rsa_public_key_from_file("RSA_publickey.pem",&testrsa);
    // print_rsa_ref_public_key(&testrsa);


    return 0;
}
