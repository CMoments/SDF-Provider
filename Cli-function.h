int Test_Device();
int Test_Session();
int Test_GetDeviceInfo();
int Test_GenerateRandom();
int Test_PrivateKeyAccessRight();
int Test_ExportSignPublicKey_RSA(unsigned int KeyIndex);
int Test_ExportEncPublic_RSA(unsigned int KeyIndex);


int Test_GenerateKeyWithIPK_RSA(unsigned int KeyIndex);
int Test_GenerateKeyWithEPK_RSA(unsigned int KeyIndex);

int Test_ImportKeyWithISK_RSA(unsigned int KeyIndex);
int Test_ExportSignPublicKey_ECC(unsigned int KeyIndex);
int Test_ExportEncPublicKey_ECC(unsigned int KeyIndex);

int Test_GenerateKeyWithIPK_ECC(unsigned int KeyIndex);
int Test_GenerateKeyWithEPK_ECC(unsigned int KeyIndex);

int Test_ImportKeyWithISK_ECC(unsigned int KeyIndex);
int Test_GenerateAgreementDataWithECC();
int Test_GenerateKeyWithECC();
int Test_GenerateAgreementDataAndKeyWithECC();
int Test_GenerateKeyWithKEK(unsigned int KeyIndex);
int Test_ImportKeyWithKEK(unsigned int KeyIndex);
int Test_DestroyKey();
int Test_ExternalPublicKeyOperation_RSA();
int Test_InternalPublicKeyOperation_RSA();
int Test_InternalPrivateKeyOperation_RSA();
int Test_ExternalVerify_ECC();
int Test_InternalSign_ECC();
int Test_InternalVerify_ECC();
int Test_ExternalEncrypt_ECC();
int Test_Encrypt();
int Test_Decrypt();
int Test_CalculateMAC();
int Test_AuthEnc();
int Test_AuthDec();



int Test_EncryptInit();
int Test_EncryptUpdate();
int Test_EncryptFinal();
int Test_DecryptInit();
int Test_DecryptUpdate();
int Test_DecryptFinal();
int Test_CalculateMACInit();
int Test_CalculateMACUpdate();
int Test_CalculateMACFinal();
int Test_AuthEncInit();
int Test_AuthEncUpdate();
int Test_AuthEncFinal();
int Test_AuthDecInit();
int Test_AuthDecUpdate();
int Test_AuthDecFinal();
int Test_HMACInit();
int Test_HMACUpdate();
int Test_HMACFinal();
int Test_HashInit();
int Test_HashUpdate();
int Test_HashFinal();
int Test_CreateFile();
int Test_ReadFile();
int Test_WriteFile();
int Test_DeleteFile();
int Test_GenerateKeyPair_RSA();
int Test_GenerateKeyPair_ECC();
int Test_ExternalPrivateKeyOperation_RSA();
int Test_ExternalSign_ECC();
int Test_ExternalDecrypt_ECC();
int Test_ExternalSign_SM9();
int Test_ExternalDecrypt_SM9();
int Test_ExternalKeyEncrypt();
int Test_ExternalKeyDecrypt();
int Test_ExternalKeyEncryptInit();
int Test_ExternalKeyDecryptInit();
int Test_ExternalKeyHMACInit();



void ExtRSAOptTest();
void IntRSAOptTest();
void IntECCSignTest();
void ExtECCOptTest();
void ExtECCSignTest();
// void IntECCOptTest();

void SymmEncDecTest();

typedef struct 
{
    const char *name;
    int (*func)();
} testcase_t;

void Test_all();

// Global test result counters defined in main.c
extern int pass;
extern int fail;
extern int notsupport;
