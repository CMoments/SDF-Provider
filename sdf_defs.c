#include "sdf_defs.h"
#include <stdio.h>
#include <string.h>
// #include "GM/T-0006.h"


// sdf_defs.c
const char* SDF_GetErrorString(int err) {
    switch (err) {
        case SDR_OK: return "SDR_OK";
        case SDR_UNKNOWERR: return "SDR_UNKNOWERR";
        case SDR_NOTSUPPORT: return "SDR_NOTSUPPORT";
        case SDR_COMMFAIL: return "SDR_COMMFAIL";
        case SDR_HARDFAIL: return "SDR_HARDFAIL";
        case SDR_OPENDEVICE: return "SDR_OPENDEVICE";
        case SDR_OPENSESSION: return "SDR_OPENSESSION";
        case SDR_PARDENY: return "SDR_PARDENY";
        case SDR_KEYNOTEXIST: return "SDR_KEYNOTEXIST";
        case SDR_ALGNOTSUPPORT: return "SDR_ALGNOTSUPPORT";
        case SDR_ALGMODNOTSUPPORT: return "SDR_ALGMODNOTSUPPORT";
        case SDR_PKOPERR: return "SDR_PKOPERR";
        case SDR_SKOPERR: return "SDR_SKOPERR";
        case SDR_SIGNERR: return "SDR_SIGNERR";
        case SDR_VERIFYERR: return "SDR_VERIFYERR";
        case SDR_SYMOPERR: return "SDR_SYMOPERR";
        case SDR_STEPERR: return "SDR_STEPERR";
        case SDR_FILESIZEERR: return "SDR_FILESIZEERR";
        case SDR_FILENOEXIST: return "SDR_FILENOEXIST";
        case SDR_FILEOFSERR: return "SDR_FILEOFSERR";
        case SDR_KEYTYPEERR: return "SDR_KEYTYPEERR";
        case SDR_KEYERR: return "SDR_KEYERR";
        case SDR_ENCDATAERR: return "SDR_ENCDATAERR";
        case SDR_RANDERR: return "SDR_RANDERR";
        case SDR_PRKRERR: return "SDR_PRKRERR";
        case SDR_MACERR: return "SDR_MACERR";
        case SDR_FILEEXISTS: return "SDR_FILEEXISTS";
        case SDR_FILEWERR: return "SDR_FILEWERR";
        case SDR_NOBUFFER: return "SDR_NOBUFFER";
        case SDR_INARGERR: return "SDR_INARGERR";
        case SDR_OUTARGERR: return "SDR_OUTARGERR";
        case SDR_USERIDERR: return "SDR_USERIDERR";


         // 通用错误
        case SWR_INVALID_PARAMETERS:
            return "Invalid parameters";
        case SWR_FILE_ALREADY_EXIST:
            return "File already exists";
        case SWR_SEM_TIMEOUT:
            return "Semaphore timeout";
        case SWR_CONFIG_ERR:
            return "Configuration error";
            
        // 硬件错误
        case SWR_CARD_UNKNOWERR:
            return "Unknown hardware error";
        case SWR_CARD_NOTSUPPORT:
            return "Unsupported interface call";
        case SWR_CARD_COMMFALL:
            return "Device communication failure";
        case SWR_CARD_HARDFALL:
            return "Crypto module no response";
        case SWR_CARD_OPENDEVICE:
            return "Open device failed";
        case SWR_CARD_OPENSESSION:
            return "Create session failed";
        case SWR_CARD_PARDENY:
            return "No private key access permission";
        case SWR_CARD_KEYNOTEXIST:
            return "Non-existent key call";
        case SWR_CARD_ALGNOTSUPPORT:
            return "Unsupported algorithm call";
        case SWR_CARD_ALGMODNOTSUPPORT:
            return "Unsupported algorithm mode call";
        case SWR_CARD_PKOPERR:
            return "Public key operation failed";
        case SWR_CARD_SKOPERR:
            return "Private key operation failed";
        case SWR_CARD_SIGNERR:
            return "Signature operation failed";
        case SWR_CARD_VERIFYERR:
            return "Signature verification failed";
        case SWR_CARD_SYMOPERR:
            return "Symmetric algorithm operation failed";
        case SWR_CARD_STEPERR:
            return "Multi-step operation sequence error";
        case SWR_CARD_FILESIZEERR:
            return "File size exceeds limit";
        case SWR_CARD_FILENOEXIST:
            return "Specified file does not exist";
        case SWR_CARD_FILEOFSERR:
            return "File offset error";
        case SWR_CARD_KEYTYPEERR:
            return "Key type error";
        case SWR_CARD_KEYERR:
            return "Key error";
        case SWR_CARD_BUFFER_TOO_SMALL:
            return "Buffer too small for parameters";
        case SWR_CARD_DATA_PAD:
            return "Data not properly padded";
        case SWR_CARD_DATA_SIZE:
            return "Plaintext/ciphertext length does not meet algorithm requirements";
        case SWR_CARD_CRYPTO_NOT_INIT:
            return "Crypto operation not initialized";
        case SWR_CARD_MANAGEMENT_DENY:
            return "Management permission denied";
        case SWR_CARD_OPERATION_DENY:
            return "Operation permission denied";
        case SWR_CARD_DEVICE_STATUS_ERR:
            return "Device status does not satisfy operation";
        case SWR_CARD_LOGIN_ERR:
            return "Login failed";
        case SWR_CARD_USERID_ERR:
            return "User ID number/quantity error";
        case SWR_CARD_PARAMENT_ERR:
            return "Parameter error";
            
        // 读卡器错误
        case SWR_CARD_READER_PIN_ERR:
            return "PIN password error";
        case SWR_CARD_READER_NO_CARD:
            return "IC card not inserted";
        case SWR_CARD_READER_CARD_INSERT:
            return "IC card insertion direction error or not in place";
        case SWR_CARD_READER_CARD_TYPE:
            return "IC card type error";
        default:
            // 如果不是自定义错误码，返回原始错误描述
            return SDF_GetErrorString(err);
    }
}

// #define SDR_GMSSLERR	(SDR_BASE + 0x00000100)

// static const uint8_t zeros[ECCref_MAX_LEN - 32] = {0};


// #define SOFTSDF_MAX_KEY_SIZE	64

// struct SOFTSDF_KEY {
// 	uint8_t key[SOFTSDF_MAX_KEY_SIZE];
// 	size_t key_size;
// 	struct SOFTSDF_KEY *next;
// };

// typedef struct SOFTSDF_KEY SOFTSDF_KEY;


// #include <gmssl/mem.h>
// #include <gmssl/sm2.h>
// #include <gmssl/sm3.h>
// #include <gmssl/sm4_cbc_mac.h>
// #include <gmssl/rand.h>
// #include <gmssl/error.h>
// struct SOFTSDF_CONTAINER {
// 	unsigned int key_index;
// 	SM2_KEY sign_key;
// 	SM2_KEY enc_key;
// 	struct SOFTSDF_CONTAINER *next;
// };
// typedef struct SOFTSDF_CONTAINER SOFTSDF_CONTAINER;

// struct SOFTSDF_SESSION {
// 	SOFTSDF_CONTAINER *container_list;
// 	SOFTSDF_KEY *key_list;
// 	SM3_CTX sm3_ctx;
// 	struct SOFTSDF_SESSION *next;
// };
// typedef struct SOFTSDF_SESSION SOFTSDF_SESSION;

// struct SOFTSDF_DEVICE {
// 	SOFTSDF_SESSION *session_list;
// };
// typedef struct SOFTSDF_DEVICE SOFTSDF_DEVICE;

// SOFTSDF_DEVICE *deviceHandle = NULL;





// #include<openssl/rsa.h>
// #include<openssl/bn.h>
// int SDF_GenerateKeyPair_RSA(
//     void *hSession,
//     unsigned int keyBits, 
//     RSArefPublicKey *pubKey, 
//     RSArefPrivateKey *priKey) {
//     // Implementation of RSA key pair generation
//     // 厂商管理工具API， 这类API（不论是厂商扩展还是管理命令）主要用于设备出厂、首次初始化、密钥轮换等场景。
//     // 一般只允许管理员或厂商工程师在安全环境下操作，普通业务系统不会直接调用。

//     int ret = SDR_OK;
//     RSA *rsa = NULL;
//     BIGNUM *e = NULL;

//     if(!pubKey || !priKey)
//         return SDR_INARGERR;
//     if(keyBits != 1024 && keyBits != 2048 && keyBits != 3072 && keyBits != 4096)
//         return SDR_INARGERR;
//     rsa = RSA_new();
//     e = BN_new();
//     BN_set_word(e, RSA_F4);

//     if(!RSA_generate_key_ex(rsa,keyBits,e,NULL)) {
//         ret = SDR_GMSSLERR;
//         goto end;
//     }
//     pubKey->bits = keyBits;
//     BN_bn2binpad(RSA_get0_n(rsa), pubKey->m, RSAref_MAX_LEN);
//     BN_bn2binpad(RSA_get0_e(rsa), pubKey->e, RSAref_MAX_LEN);

//     priKey->bits = keyBits;
//     BN_bn2binpad(RSA_get0_n(rsa), priKey->m, RSAref_MAX_LEN);
//     BN_bn2binpad(RSA_get0_e(rsa), priKey->e, RSAref_MAX_LEN);
//     BN_bn2binpad(RSA_get0_d(rsa), priKey->d, RSAref_MAX_LEN);
//     BN_bn2binpad(RSA_get0_p(rsa), priKey->prime[0], RSAref_MAX_LEN);
//     BN_bn2binpad(RSA_get0_q(rsa), priKey->prime[1], RSAref_MAX_LEN);
//     BN_bn2binpad(RSA_get0_dmp1(rsa), priKey->pexp[0], RSAref_MAX_LEN);
//     BN_bn2binpad(RSA_get0_dmq1(rsa), priKey->pexp[1], RSAref_MAX_LEN);
//     BN_bn2binpad(RSA_get0_iqmp(rsa), priKey->coef, RSAref_MAX_LEN);

// end:
//     RSA_free(rsa);
//     BN_free(e);
//     return SDR_OK;
// }

// int SDF_GenerateKeyPair_ECC(
// 	void *hSessionHandle,
// 	unsigned int uiAlgID,
// 	unsigned int uiKeyBits,
// 	ECCrefPublicKey *pucPublicKey,
// 	ECCrefPrivateKey *pucPrivateKey)
// {
// 	SOFTSDF_SESSION *session;
// 	SM2_KEY sm2_key;
// 	SM2_POINT public_key;
// 	uint8_t private_key[32];

// 	if (deviceHandle == NULL) {
// 		error_print();
// 		return SDR_STEPERR;
// 	}

// 	if (hSessionHandle == NULL) {
// 		error_puts("Invalid session handle");
// 		return SDR_INARGERR;
// 	}
// 	session = deviceHandle->session_list;
// 	while (session != NULL && session != hSessionHandle) {
// 		session = session->next;
// 	}
// 	if (session == NULL) {
// 		error_print();
// 		return SDR_INARGERR;
// 	}

// 	if (uiAlgID != SGD_SM2_1 && uiAlgID != SGD_SM2_3) {
// 		error_print();
// 		return SDR_INARGERR;
// 	}

// 	if (uiKeyBits != 256) {
// 		error_print();
// 		return SDR_INARGERR;
// 	}

// 	if (pucPublicKey == NULL || pucPrivateKey == NULL) {
// 		error_print();
// 		return SDR_INARGERR;
// 	}

// 	if (sm2_key_generate(&sm2_key) != 1) {
// 		error_print();
// 		return SDR_GMSSLERR;
// 	}

// 	sm2_z256_to_bytes(sm2_key.private_key, private_key);
// 	sm2_z256_point_to_bytes(&sm2_key.public_key, (uint8_t *)&public_key);

// 	memset(pucPublicKey, 0, sizeof(*pucPublicKey));
// 	pucPublicKey->bits = 256;
// 	memcpy(pucPublicKey->x + ECCref_MAX_LEN - 32, public_key.x, 32);
// 	memcpy(pucPublicKey->y + ECCref_MAX_LEN - 32, public_key.y, 32);

// 	memset(pucPrivateKey, 0, sizeof(*pucPrivateKey));
// 	pucPrivateKey->bits = 256;
// 	memcpy(pucPrivateKey->K + ECCref_MAX_LEN - 32, private_key, 32);

// 	memset(&sm2_key, 0, sizeof(sm2_key));
// 	memset(private_key, 0, sizeof(private_key));
// 	return SDR_OK;
// }