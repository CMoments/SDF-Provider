#pragma once
#define RSAref_MAX_BITS 2048
#define RSAref_MAX_LEN ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN ((RSAref_MAX_PBITS + 7) / 8)

#define ECCref_MAX_BITS 512
#define ECCref_MAX_LEN ((ECCref_MAX_BITS + 7) / 8)
#define SGD_SM2_3 0x00020800


#define SM9ref_MAX_BITS 256
#define SM9ref_MAX_LEN ((SM9ref_MAX_BITS + 7) / 8)


typedef struct DeviceInfo_st{
    unsigned char IssuerName[40];
    unsigned char SerialNumber[16];
    unsigned char FirmwareVersion[16];
    unsigned int DeviceVersion;
    unsigned int StandardVersion;
    unsigned int AsymAlgAbility[2];
    unsigned int SymAlgAbility;
    unsigned int HashAlgAbility;
    unsigned int BufferSize;
} DEVICEINFO;

typedef struct RSArefPublicKey_st{
    unsigned int bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;
typedef struct RSArefPrivateKey_st{
    unsigned int bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
    unsigned char d[RSAref_MAX_LEN];
    unsigned char prime[2][RSAref_MAX_PLEN];
    unsigned char pexp[2][RSAref_MAX_PLEN];
    unsigned char coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;

typedef struct ECCrefPublicKey_st{
    unsigned int bits;
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
} ECCrefPublicKey;
typedef struct ECCrefPrivateKey_st
{
    unsigned int bits;
    unsigned char K[ECCref_MAX_LEN];
} ECCrefPrivateKey;
typedef struct ECCCipher_st{
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
    unsigned char M[32];
    unsigned int L;
	unsigned char C[1];
	// Extend sizeof(C) to SM2_MAX_PLAINTEXT_SIZE
	// gmssl/sm2.h: SM2_MAX_PLAINTEXT_SIZE = 255
	// unsigned char C_[254];
    // unsigned char *C;
} ECCCipher;
typedef struct ECCSignature_st{
    unsigned char r[ECCref_MAX_LEN];
    unsigned char s[ECCref_MAX_LEN];
} ECCSignature;


typedef struct SM9refMasterPrivateKey_st
{
    unsigned int bits;
    unsigned char s[SM9ref_MAX_LEN];
} SM9MasterPrivateKey;

typedef struct SM9refSignMasterPublicKey_st{
    unsigned int bits;
    unsigned char xa[SM9ref_MAX_LEN];
    unsigned char xb[SM9ref_MAX_LEN];
    unsigned char ya[SM9ref_MAX_LEN];
    unsigned char yb[SM9ref_MAX_LEN];
} SM9SignMasterPublicKey;

typedef struct SM9refEncMasterPublicKey_st{
    unsigned int bits;
    unsigned char x[SM9ref_MAX_LEN];
    unsigned char y[SM9ref_MAX_LEN];
} SM9EncMasterPublicKey;

typedef struct  SM9refSignUserPrivateKey_st
{
    unsigned int bits;
    unsigned char x[SM9ref_MAX_LEN];
    unsigned char y[SM9ref_MAX_LEN];
}SM9SignUserPrivateKey;

typedef struct  SM9refEncUserPrivateKey_st
{
    unsigned int bits;
    unsigned char xa[SM9ref_MAX_LEN];
    unsigned char xb[SM9ref_MAX_LEN];
    unsigned char ya[SM9ref_MAX_LEN];
    unsigned char yb[SM9ref_MAX_LEN];
}SM9EncUserPrivateKey;

typedef struct SM9refCipher_st
{
    unsigned int EncType;
    unsigned char x[SM9ref_MAX_LEN];
    unsigned char y[SM9ref_MAX_LEN];
    char h[32];
    unsigned int L;
    unsigned char C[];
}SM9Cipher;
typedef struct SM9refSignature_st{
    unsigned char h[SM9ref_MAX_LEN];
    unsigned char x[SM9ref_MAX_LEN];
    unsigned char y[SM9ref_MAX_LEN];
} SM9Signature;

typedef struct SM9refKeyPackage_st{
    unsigned char x[SM9ref_MAX_LEN];
    unsigned char y[SM9ref_MAX_LEN];
} SM9KeyPackage;
typedef struct SM9refEncEnvelopedKey_st{
    unsigned int version;
    unsigned int ulSymmAlgID;
    unsigned int bits;
    unsigned char encryptedPriKey[SM9ref_MAX_LEN * 4];
    SM9EncMasterPublicKey encMastPubKey;
    SM9EncMasterPublicKey tempMastPubKey;
    unsigned int userIDLen;
    unsigned char userID[256];
    unsigned int keyLen;
    SM9KeyPackage keyPackage;
} SM9EncEnveploedKey;
    


    // 设备管理类(8)
    typedef int (*SDF_OpenDevice)(void**);
    typedef int (*SDF_CloseDevice)(void**);
    typedef int (*SDF_OpenSession)(void *hDeviceHandle, void **phSessionHandle);
    typedef int (*SDF_CloseSession)(void *hSessionHandle);
    typedef int (*SDF_GetDeviceInfo)(void *hDeviceHandle, DEVICEINFO *pstDeviceInfo);
    typedef int (*SDF_GenerateRandom)(void *hSessionHandle, unsigned int uiLength, unsigned char *pucRandom);
    typedef int (*SDF_GetPrivateKeyAccessRight)(void *hSessionHandle, unsigned int uiKeyIndex, char *pucPassword, unsigned int uiPwdLength);
    typedef int (*SDF_ReleasePrivateKeyAccessRight)(void *hSessionHandle, unsigned int uiKeyIndex);


    // 密钥管理类(16)
    //NOT SUPPORTED 
    typedef int (*SDF_ExportSignPublicKey_RSA)(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pubPublicKey);
    typedef int (*SDF_ExportEncPublicKey_RSA)(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pubPublicKey);
    typedef int (*SDF_GenerateKeyWithIPK_RSA)(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiKeyBits, unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle);
    typedef int (*SDF_GenerateKeyWithEPK_RSA)(void *hSessionHandle, unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey, unsigned char *pubKcy, unsigned int *puiKeyLength, void **phKeyHandle);
    typedef int (*SDF_ImportKeyWithISK_RSA)(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucKey, unsigned int PuiKeyLength, void **phKeyHandle);
    //SUPPORTED
    typedef int (*SDF_ExportSignPublicKey_ECC)(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey);
    typedef int (*SDF_ExportEncPublicKey_ECC)(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey);
    typedef int (*SDF_GenerateKeyWithIPK_ECC)(void *hSessionHandle, unsigned int uiIPKIndex, unsigned int uiKeyBits, ECCCipher *pucKey, void **phKeyHandle);
    typedef int (*SDF_GenerateKeyWithEPK_ECC)(void *hSessionHandle, unsigned int uiKeyBits, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey, void **phKeyHandle);
    typedef int (*SDF_ImportKeyWithISK_ECC)(void *hSessionHandle, unsigned int uiISKIndex, ECCCipher *pucKey, void **phKeyHandle);
    //NOT SUPPORTED
    typedef int (*SDF_GenerateAgreementDataWithECC)(void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits, unsigned char *pucSponsorID,unsigned int uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey, void ** phAgreementHandle);
    typedef int (*SDF_GenerateKeyWithECC)(void *hSessionHandle, unsigned char *pucResponseID, unsigned int uiResponseIDLength, ECCrefPublicKey *pucResponsePublicKey, ECCrefPublicKey *pucResponseTmpPublicKey, void *hAgreementHandle, void **phKeyHandle);
    typedef int (*SDF_GenerateAgreementDataAndKeyWithECC)(
        void *hSessionHandle, 
        unsigned int uiISKIndex, 
        unsigned int uiKeyBits, 
        unsigned char *pucResponseID, 
        unsigned int uiResponseIDLength, 
        unsigned char *pucSponsorID,
        unsigned int uiSponsorIDLength,
        ECCrefPublicKey *pucSponsorPublicKey, 
        ECCrefPublicKey *pucSponsorTmpPublicKey, 
        ECCrefPublicKey *pucResponsePublicKey, 
        ECCrefPublicKey *pucResponseTmpPublicKey, 
        void **phKeyHandle);
    //SUPPORTED
    typedef int (*SDF_GenerateKeyWithKEK)(void *hSessionHandle, unsigned int uiKeyBits, unsigned int uiAlgID, unsigned int uiKEKIndex, unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle);
    typedef int (*SDF_ImportKeyWithKEK)(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKEKIndex, unsigned char *pucKey, unsigned int uiKeyLength, void **phKeyHandle);
    typedef int (*SDF_DestroyKey)(void *hSessionHandle, void *hKeyHandle);


    // 非对称运算类(7)
    typedef int (*SDF_ExternalPublicKeyOperation_RSA)(void *hSessionHandle, RSArefPublicKey *pucPublicKey, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
    typedef int (*SDF_InternalPublicKeyOperation_RSA)(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
    typedef int (*SDF_InternalPrivateKeyOperation_RSA)(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
    typedef int (*SDF_ExternalVerify_ECC)(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, unsigned char *pucDataInput, unsigned int uiInputLength, ECCSignature *pucSignature);
    typedef int (*SDF_InternalSign_ECC)(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucData, unsigned int uiDataLength, ECCSignature *pucSignature);
    typedef int (*SDF_InternalVerify_ECC)(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucData, unsigned int uiDataLength, ECCSignature *pucSignature);
    typedef int (*SDF_ExternalEncrypt_ECC)(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, unsigned char* pucData, unsigned int uiDataLength, ECCCipher *pucEncData);


    // 对称算法运算类(20)
    typedef int (*SDF_Encrypt)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned char*pucData,unsigned int uiDataLength,unsigned char *pucEncData, unsigned int *puiEncDataLength);
    typedef int (*SDF_Decrypt)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength);
    typedef int (*SDF_CalculateMAC)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,unsigned char *pucData,unsigned int uiDataLength,unsigned char *pucMAC, unsigned int *puiMACLength);
    typedef int (*SDF_AuthEnc)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucStartVar, unsigned int uiStartVarLength, unsigned char *pucAad, unsigned int uiAadLength, unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength, unsigned char *pucAuthData, unsigned int *puiAuthDataLength);
    typedef int (*SDF_AuthDec)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucStartVar, unsigned int uiStartVarLength, unsigned char *pucAad, unsigned int uiAadLength, unsigned char *pucAuthData, unsigned int *puiAuthDataLength, unsigned char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength);
    typedef int (*SDF_EncryptInit)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned int uiIVLength);
    typedef int (*SDF_EncryptUpdate)(void *hSessionHandle, char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength);
    typedef int (*SDF_EncryptFinal)(void *hSessionHandle, unsigned char *pucLastEncData, unsigned int *puiLastEncDataLength);
    typedef int (*SDF_DecryptInit)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned int uiIVLength);
    typedef int (*SDF_DecryptUpdate)(void *hSessionHandle, char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength);
    typedef int (*SDF_DecryptFinal)(void *hSessionHandle, unsigned char *pucLastData, unsigned int *puiLastDataLength);
    typedef int (*SDF_CalculateMACInit)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned int uiIVLength);
    typedef int (*SDF_CalculateMACUpdate)(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength);
    typedef int (*SDF_CalculateMACFinal)(void *hSessionHandle, unsigned char *pucMac, unsigned int *puiMacLength);
    typedef int (*SDF_AuthEncInit)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucStartVar, unsigned int uiStartVarLength, unsigned char *pucAad, unsigned int uiAadLength, unsigned int uiDataLength);
    typedef int (*SDF_AuthEncUpdate)(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength);
    typedef int (*SDF_AuthEncFinal)(void *hSessionHandle, unsigned char *pucLastEncData, unsigned int *puiLastEncDataLength, unsigned char *pucAuthData, unsigned int *puiAuthDataLength);
    typedef int (*SDF_AuthDecInit)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucStartVar, unsigned int uiStartVarLength, unsigned char *pucAad, unsigned int uiAadLength, unsigned char *pucAuthData, unsigned int uiAuthDataLength, unsigned int uiDataLength);
    typedef int (*SDF_AuthDecUpdate)(void *hSessionHandle, unsigned char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength);
    typedef int (*SDF_AuthDecFinal)(void *hSessionHandle, unsigned char *pucLastData, unsigned int *puLastDataLength);


    // 杂凑运算类(6)
    typedef int (*SDF_HMACInit)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID);
    typedef int (*SDF_HMACUpdate)(void *hSessionHandle, char *pucData, unsigned int uiDataLength);
    typedef int (*SDF_HMACFinal)(void *hSessionHandle, char *pucHMac, unsigned int *puiMacLength);
    typedef int (*SDF_HashInit)(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, char *pucID, unsigned int uiIDLength);
    typedef int (*SDF_HashUpdate)(void *hSessionHandle, char *pucData, unsigned int uiDataLength);
    typedef int (*SDF_HashFinal)(void *hSessionHandle, char *pucHash, unsigned int *puiHashLength);

    // 用户文件操作类(4)
    typedef int (*SDF_CreateFile)(void *hSessionHandle, char *pucFileName, unsigned int uiNameLen, unsigned int uiFileSize);
    typedef int (*SDF_ReadFile)(void *hSessionHandle, char *pucfileName, unsigned int uiNameLen, unsigned int uiOffset, unsigned int *puiFileLength,unsigned char *pucBuffer);
    typedef int (*SDF_WriteFile)(void *hSessionHandle, char *pucFileName, unsigned int uiNamelen, unsigned int uiOffset, unsigned int uiFileLength, char *pucBuffer);
    typedef int (*SDF_DeleteFile)(void *hSessionHandle, char *pucFileName, unsigned int uiNameLen);

    // 验证调试类(12)
    typedef int (*SDF_GenerateKeyPair_RSA)(unsigned int uiKeyBits, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey);
    typedef int (*SDF_GenerateKeyPair_ECC)(unsigned int uiAlgID, unsigned int uiKeyBits, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);
    // typedef int (*SDF_ExternalPrivateKeyOperation_RSA)(RSArefPrivateKey *pucPrivateKey, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
    // 标准接口没有使用hSession，这里为了兼容三卫信安
    typedef int (*SDF_ExternalPrivateKeyOperation_RSA)(void *hSession,RSArefPrivateKey *pucPrivateKey, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
    //ExternalSign_ECC使用了hSession，这里为了兼容三卫信安
    // typedef int (*SDF_ExternalSign_ECC)(unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey, unsigned char *pucDataInput, unsigned int uiInputLength, ECCSignature *pucSignature);
    typedef int (*SDF_ExternalSign_ECC)(void *hSession,unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey, unsigned char *pucDataInput, unsigned int uiInputLength, ECCSignature *pucSignature);
    //ExternalDecrypt_ECC使用了hSession，这里为了兼容三卫信安
    typedef int (*SDF_ExternalDecrypt_ECC)(void *hSession,unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey, ECCCipher *pucEncData, unsigned char *pucData, unsigned int *uiDataLength);
    typedef int (*SDF_ExternalSign_SM9)(SM9SignMasterPublicKey *pSignMasterPublicKey, SM9SignUserPrivateKey *pSignUserPrivateKey, unsigned char *pucData, unsigned int uiDataLength, SM9Signature *pSignature);
    typedef int (*SDF_ExternalDecrypt_SM9)(SM9EncUserPrivateKey *pEncUserPrivateKey, unsigned char *pucUserID, unsigned int uiUserIDLen, unsigned char *pucIV, unsigned char *pucData, unsigned int uiDataLength, SM9Cipher *pEncData);
    typedef int (*SDF_ExternalKeyEncrypt)(unsigned int uiAlgID, unsigned char *pucKey, unsigned int uiKeyLength, unsigned char *pucIV, unsigned int uiIVLength, unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength);
    typedef int (*SDF_ExternalKeyDecrypt)(
        unsigned int uiAlgID, 
        unsigned char *pucKey, 
        unsigned int uiKeyLength, 
        unsigned char *pucIV,
        unsigned int uiIVLength,
        unsigned char *pucEncData, 
        unsigned int uiEncDataLength,
        unsigned char *pucData, 
        unsigned int *puiDataLength);
    typedef int (*SDF_ExternalKeyEncryptInit)(void *hSessionHandle, unsigned int uiAlgID, unsigned char *pucKey, unsigned int uiKeyLength, unsigned char *pucIV, unsigned int uiIVLength);
    typedef int (*SDF_ExternalKeyDecryptInit)(void *hSessionHandle, unsigned int uiAlgID, unsigned char *pucKey, unsigned int uiKeyLength, unsigned char *pucIV, unsigned int uiIVLength);
    typedef int (*SDF_ExternalKeyHMACInit)(void *hSessionHandle, unsigned int uiAlgID, unsigned char *pucKey, unsigned int uiKeyLength);


// 扩展接口
    typedef int  (*SDF_InternalEncrypt_ECC)(void *hSessionHandle, unsigned int uiIPKIndex,unsigned int uiAlgID, unsigned char *pucData, unsigned int uiDataLength, ECCCipher *pucEncData);
    typedef int  (*SDF_InternalDecrypt_ECC)(void *hSessionHandle, unsigned int uiISKIndex,unsigned int uiAlgID, ECCCipher *pucEncData, unsigned char *pucData, unsigned int *puiDataLength);

    const char *SDF_GetErrorString(int err);

    /* 错误码基础值 */
#define SDR_BASE 0x01000000

    /* 操作成功 */
#define SDR_OK 0x00000000

    /* 通用错误码 */
#define SDR_UNKNOWERR (SDR_BASE + 0x00000001)        /* 未知错误 */
#define SDR_NOTSUPPORT (SDR_BASE + 0x00000002)       /* 不支持的接口调用 */
#define SDR_COMMFAIL (SDR_BASE + 0x00000003)         /* 与设备通信失败 */
#define SDR_HARDFAIL (SDR_BASE + 0x00000004)         /* 运算模块无响应 */
#define SDR_OPENDEVICE (SDR_BASE + 0x00000005)       /* 打开设备失败 */
#define SDR_OPENSESSION (SDR_BASE + 0x00000006)      /* 创建会话失败 */
#define SDR_PARDENY (SDR_BASE + 0x00000007)          /* 无私钥使用权限 */
#define SDR_KEYNOTEXIST (SDR_BASE + 0x00000008)      /* 不存在的密钥调用 */
#define SDR_ALGNOTSUPPORT (SDR_BASE + 0x00000009)    /* 不支持的算法调用 */
#define SDR_ALGMODNOTSUPPORT (SDR_BASE + 0x0000000A) /* 不支持的算法模式调用 */
#define SDR_PKOPERR (SDR_BASE + 0x0000000B)          /* 公钥运算失败 */
#define SDR_SKOPERR (SDR_BASE + 0x0000000C)          /* 私钥运算失败 */
#define SDR_SIGNERR (SDR_BASE + 0x0000000D)          /* 签名运算失败 */
#define SDR_VERIFYERR (SDR_BASE + 0x0000000E)        /* 验证签名失败 */
#define SDR_SYMOPERR (SDR_BASE + 0x0000000F)         /* 对称算法运算失败 */
#define SDR_STEPERR (SDR_BASE + 0x00000010)          /* 多步运算步骤错误 */
#define SDR_FILESIZEERR (SDR_BASE + 0x00000011)      /* 文件长度超出限制 */
#define SDR_FILENOEXIST (SDR_BASE + 0x00000012)      /* 指定的文件不存在 */
#define SDR_FILEOFSERR (SDR_BASE + 0x00000013)       /* 文件起始位置错误 */
#define SDR_KEYTYPEERR (SDR_BASE + 0x00000014)       /* 密钥类型错误 */
#define SDR_KEYERR (SDR_BASE + 0x00000015)           /* 密钥错误 */
#define SDR_ENCDATAERR (SDR_BASE + 0x00000016)       /* ECC 加密数据错误 */
#define SDR_RANDERR (SDR_BASE + 0x00000017)          /* 随机数产生失败 */
#define SDR_PRKRERR (SDR_BASE + 0x00000018)          /* 私钥使用权限获取失败 */
#define SDR_MACERR (SDR_BASE + 0x00000019)           /* MAC 运算失败 */
#define SDR_FILEEXISTS (SDR_BASE + 0x0000001A)       /* 指定文件已存在 */
#define SDR_FILEWERR (SDR_BASE + 0x0000001B)         /* 文件写入失败 */
#define SDR_NOBUFFER (SDR_BASE + 0x0000001C)         /* 存储空间不足 */
#define SDR_INARGERR (SDR_BASE + 0x0000001D)         /* 输入参数错误 */
#define SDR_OUTARGERR (SDR_BASE + 0x0000001E)        /* 输出参数错误 */
#define SDR_USERIDERR (SDR_BASE + 0x0000001F)        /* 用户标识错误 */

    /* 0x20–0xFFFFFF 区段为预留，如需自定义错误码，请从 0x00000020 起按顺序定义 */


#define SWR_BASE (SDR_BASE + 0x00010000)
// 通用错误码
#define SWR_INVALID_PARAMETERS    (SWR_BASE + 0x00000005)    // 参数错误
#define SWR_FILE_ALREADY_EXIST    (SWR_BASE + 0x00000006)    // 已存在同名文件
#define SWR_SEM_TIMEOUT           (SWR_BASE + 0x00000200)    // 超时错误
#define SWR_CONFIG_ERR            (SWR_BASE + 0x00000301)    // 配置文件错误

// 密码卡硬件错误码基础值
#define SWR_CARD_BASE             (SDR_BASE + 0x00020000)

// 密码卡硬件错误码
#define SWR_CARD_UNKNOWERR        (SWR_CARD_BASE + 0x00000001)  // 未知硬件错误
#define SWR_CARD_NOTSUPPORT       (SWR_CARD_BASE + 0x00000002)  // 不支持的接口调用
#define SWR_CARD_COMMFALL         (SWR_CARD_BASE + 0x00000003)  // 与设备通信失败
#define SWR_CARD_HARDFALL         (SWR_CARD_BASE + 0x00000004)  // 运算模块无响应
#define SWR_CARD_OPENDEVICE       (SWR_CARD_BASE + 0x00000005)  // 打开设备失败
#define SWR_CARD_OPENSESSION      (SWR_CARD_BASE + 0x00000006)  // 创建会话失败
#define SWR_CARD_PARDENY          (SWR_CARD_BASE + 0x00000007)  // 无私钥使用权限
#define SWR_CARD_KEYNOTEXIST      (SWR_CARD_BASE + 0x00000008)  // 不存在的密钥调用
#define SWR_CARD_ALGNOTSUPPORT    (SWR_CARD_BASE + 0x00000009)  // 不支持的算法调用
#define SWR_CARD_ALGMODNOTSUPPORT (SWR_CARD_BASE + 0x00000010)  // 不支持的算法模式调用
#define SWR_CARD_PKOPERR          (SWR_CARD_BASE + 0x00000011)  // 公钥运算失败
#define SWR_CARD_SKOPERR          (SWR_CARD_BASE + 0x00000012)  // 私钥运算失败
#define SWR_CARD_SIGNERR          (SWR_CARD_BASE + 0x00000013)  // 签名运算失败
#define SWR_CARD_VERIFYERR        (SWR_CARD_BASE + 0x00000014)  // 验证签名失败
#define SWR_CARD_SYMOPERR         (SWR_CARD_BASE + 0x00000015)  // 对称算法运算失败
#define SWR_CARD_STEPERR          (SWR_CARD_BASE + 0x00000016)  // 多步运算步骤错误
#define SWR_CARD_FILESIZEERR      (SWR_CARD_BASE + 0x00000017)  // 文件长度超出限制
#define SWR_CARD_FILENOEXIST      (SWR_CARD_BASE + 0x00000018)  // 指定的文件不存在
#define SWR_CARD_FILEOFSERR       (SWR_CARD_BASE + 0x00000019)  // 文件起始位置错误
#define SWR_CARD_KEYTYPEERR       (SWR_CARD_BASE + 0x00000020)  // 密钥类型错误
#define SWR_CARD_KEYERR           (SWR_CARD_BASE + 0x00000021)  // 密钥错误
#define SWR_CARD_BUFFER_TOO_SMALL (SWR_CARD_BASE + 0x00000101)  // 接收参数的缓存区太小
#define SWR_CARD_DATA_PAD         (SWR_CARD_BASE + 0x00000102)  // 数据没有按正确格式填充
#define SWR_CARD_DATA_SIZE        (SWR_CARD_BASE + 0x00000103)  // 明文或密文长度不符合相应的算法要求
#define SWR_CARD_CRYPTO_NOT_INIT  (SWR_CARD_BASE + 0x00000104)  // 该错误表明没有为相应的算法调用初始化函数
#define SWR_CARD_MANAGEMENT_DENY  (SWR_CARD_BASE + 0x00001001)  // 管理权限不满足
#define SWR_CARD_OPERATION_DENY   (SWR_CARD_BASE + 0x00001002)  // 操作权限不满足
#define SWR_CARD_DEVICE_STATUS_ERR (SWR_CARD_BASE + 0x00001003) // 当前设备状态不满足现有操作
#define SWR_CARD_LOGIN_ERR        (SWR_CARD_BASE + 0x00001011)  // 登录失败
#define SWR_CARD_USERID_ERR       (SWR_CARD_BASE + 0x00001012)  // 用户 ID 数目/号码错误
#define SWR_CARD_PARAMENT_ERR     (SWR_CARD_BASE + 0x00001013)  // 参数错误

// 读卡器错误码基础值
#define SWR_CARD_READER_BASE      (SDR_BASE + 0x00030000)

// 读卡器错误码
#define SWR_CARD_READER_PIN_ERR   (SWR_CARD_READER_BASE + 0x000063C0)  // PIN 口令错误
#define SWR_CARD_READER_NO_CARD   (SWR_CARD_READER_BASE + 0x0000FF01)  // IC 未插入
#define SWR_CARD_READER_CARD_INSERT (SWR_CARD_READER_BASE + 0x0000FF02) // IC 插入方向错误或不到位
#define SWR_CARD_READER_CARD_TYPE (SWR_CARD_READER_BASE + 0x0000FF03)  // IC 类型错误
