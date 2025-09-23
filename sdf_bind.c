#include <dlfcn.h>
#include <stdio.h>
#include "sdf_bind.h"
#include "internal/dso.h"
#include <openssl/types.h>
#include "sdf_local.h"
SDF_OpenDevice OpenDevice = NULL;
SDF_CloseDevice CloseDevice = NULL;
SDF_OpenSession OpenSession = NULL;
SDF_CloseSession CloseSession = NULL;
SDF_GetDeviceInfo GetDeviceInfo = NULL;
SDF_GenerateRandom GenerateRandom = NULL;
SDF_GetPrivateKeyAccessRight GetPrivateKeyAccessRight = NULL;
SDF_ReleasePrivateKeyAccessRight ReleasePrivateKeyAccessRight = NULL;
SDF_ExportSignPublicKey_RSA ExportSignPublicKey_RSA = NULL;
SDF_ExportEncPublicKey_RSA ExportEncPublicKey_RSA = NULL;
SDF_GenerateKeyWithIPK_RSA GenerateKeyWithIPK_RSA = NULL;
SDF_GenerateKeyWithEPK_RSA GenerateKeyWithEPK_RSA = NULL;
SDF_ImportKeyWithISK_RSA ImportKeyWithISK_RSA= NULL;
SDF_ExportSignPublicKey_ECC ExportSignPublicKey_ECC = NULL;
SDF_ExportEncPublicKey_ECC ExportEncPublicKey_ECC = NULL;
SDF_GenerateKeyWithIPK_ECC GenerateKeyWithIPK_ECC = NULL;
SDF_GenerateKeyWithEPK_ECC GenerateKeyWithEPK_ECC = NULL;
SDF_ImportKeyWithISK_ECC ImportKeyWithISK_ECC = NULL;
SDF_GenerateAgreementDataWithECC GenerateAgreementDataWithECC = NULL;
SDF_GenerateKeyWithECC GenerateKeyWithECC = NULL;
SDF_GenerateAgreementDataAndKeyWithECC GenerateAgreementDataAndKeyWithECC = NULL;
SDF_GenerateKeyWithKEK GenerateKeyWithKEK = NULL;
SDF_ImportKeyWithKEK ImportKeyWithKEK = NULL;
SDF_DestroyKey DestroyKey = NULL;
SDF_ExternalPublicKeyOperation_RSA ExternalPublicKeyOperation_RSA = NULL;
SDF_InternalPublicKeyOperation_RSA InternalPublicKeyOperation_RSA = NULL;
SDF_InternalPrivateKeyOperation_RSA InternalPrivateKeyOperation_RSA = NULL;
SDF_ExternalVerify_ECC ExternalVerify_ECC = NULL;
SDF_InternalSign_ECC InternalSign_ECC = NULL;
SDF_InternalVerify_ECC InternalVerify_ECC = NULL;
SDF_ExternalEncrypt_ECC ExternalEncrypt_ECC = NULL;
SDF_Encrypt Encrypt = NULL;
SDF_Decrypt Decrypt = NULL;
SDF_CalculateMAC CalculateMAC = NULL;
SDF_AuthEnc AuthEnc = NULL;
SDF_AuthDec AuthDec = NULL;
SDF_EncryptInit EncryptInit = NULL;
SDF_EncryptUpdate EncryptUpdate = NULL;
SDF_EncryptFinal EncryptFinal = NULL;
SDF_DecryptInit DecryptInit = NULL;
SDF_DecryptUpdate DecryptUpdate = NULL;
SDF_DecryptFinal DecryptFinal = NULL;
SDF_CalculateMACInit CalculateMACInit = NULL;
SDF_CalculateMACUpdate CalculateMACUpdate = NULL;
SDF_CalculateMACFinal CalculateMACFinal = NULL;
SDF_AuthEncInit AuthEncInit = NULL;
SDF_AuthEncUpdate AuthEncUpdate = NULL;
SDF_AuthEncFinal AuthEncFinal = NULL;
SDF_AuthDecInit AuthDecInit = NULL;
SDF_AuthDecUpdate AuthDecUpdate = NULL;
SDF_AuthDecFinal AuthDecFinal = NULL;
SDF_HMACInit HMACInit = NULL;
SDF_HMACUpdate HMACUpdate = NULL;
SDF_HMACFinal HMACFinal = NULL;
SDF_HashInit HashInit = NULL;
SDF_HashUpdate HashUpdate = NULL;
SDF_HashFinal HashFinal = NULL;
SDF_CreateFile CreateFile = NULL;
SDF_ReadFile ReadFile = NULL;
SDF_WriteFile WriteFile = NULL;
SDF_DeleteFile DeleteFile = NULL;


SDF_GenerateKeyPair_RSA GenerateKeyPair_RSA = NULL;
SDF_GenerateKeyPair_ECC GenerateKeyPair_ECC = NULL;
SDF_ExternalPrivateKeyOperation_RSA ExternalPrivateKeyOperation_RSA = NULL;
SDF_ExternalSign_ECC ExternalSign_ECC = NULL;
SDF_ExternalDecrypt_ECC ExternalDecrypt_ECC = NULL;
SDF_ExternalSign_SM9 ExternalSign_SM9 = NULL;
SDF_ExternalDecrypt_SM9 ExternalDecrypt_SM9 = NULL;
SDF_ExternalKeyEncrypt ExternalKeyEncrypt = NULL;
SDF_ExternalKeyDecrypt ExternalKeyDecrypt = NULL;
SDF_ExternalKeyEncryptInit ExternalKeyEncryptInit = NULL;
SDF_ExternalKeyDecryptInit ExternalKeyDecryptInit = NULL;
SDF_ExternalKeyHMACInit ExternalKeyHMACInit = NULL;

int sdf_bind_init(SDF_METHOD *sdfm,DSO *dso) {
    if (sdfm == NULL) {
        fprintf(stderr, "SDF_METHOD pointer is NULL\n");
        return -1;
    }
    if (dso == NULL) {
        fprintf(stderr, "DSO object is NULL\n");
        return -1;
    }
    sdfm->OpenDevice = (SDF_OpenDevice)DSO_bind_func(dso, "SDF_OpenDevice");
    sdfm->CloseDevice = (SDF_CloseDevice)DSO_bind_func(dso, "SDF_CloseDevice");
    sdfm->OpenSession = (SDF_OpenSession)DSO_bind_func(dso, "SDF_OpenSession");
    sdfm->CloseSession = (SDF_CloseSession)DSO_bind_func(dso, "SDF_CloseSession");
    sdfm->GetDeviceInfo = (SDF_GetDeviceInfo)DSO_bind_func(dso, "SDF_GetDeviceInfo");
    sdfm->GenerateRandom = (SDF_GenerateRandom)DSO_bind_func(dso, "SDF_GenerateRandom");
    sdfm->GetPrivateKeyAccessRight = (SDF_GetPrivateKeyAccessRight)DSO_bind_func(dso, "SDF_GetPrivateKeyAccessRight");
    sdfm->ReleasePrivateKeyAccessRight = (SDF_ReleasePrivateKeyAccessRight)DSO_bind_func(dso, "SDF_ReleasePrivateKeyAccessRight");
    sdfm->ExportSignPublicKey_RSA = (SDF_ExportSignPublicKey_RSA)DSO_bind_func(dso, "SDF_ExportSignPublicKey_RSA");
    sdfm->ExportEncPublicKey_RSA = (SDF_ExportEncPublicKey_RSA)DSO_bind_func(dso, "SDF_ExportEncPublicKey_RSA");
    sdfm->GenerateKeyPair_RSA = (SDF_GenerateKeyPair_RSA)DSO_bind_func(dso, "SDF_GenerateKeyPair_RSA");
    sdfm->GenerateKeyWithIPK_RSA = (SDF_GenerateKeyWithIPK_RSA)DSO_bind_func(dso, "SDF_GenerateKeyWithIPK_RSA");
    sdfm->GenerateKeyWithEPK_RSA = (SDF_GenerateKeyWithEPK_RSA)DSO_bind_func(dso, "SDF_GenerateKeyWithEPK_RSA");
    sdfm->ImportKeyWithISK_RSA = (SDF_ImportKeyWithISK_RSA)DSO_bind_func(dso, "SDF_ImportKeyWithISK_RSA");

    
    sdfm->ExportSignPublicKey_ECC = (SDF_ExportSignPublicKey_ECC)DSO_bind_func(dso, "SDF_ExportSignPublicKey_ECC");
    sdfm->ExportEncPublicKey_ECC = (SDF_ExportEncPublicKey_ECC)DSO_bind_func(dso, "SDF_ExportEncPublicKey_ECC");
    sdfm->GenerateKeyWithIPK_ECC = (SDF_GenerateKeyWithIPK_ECC)DSO_bind_func(dso, "SDF_GenerateKeyWithIPK_ECC");
    sdfm->GenerateKeyWithEPK_ECC = (SDF_GenerateKeyWithEPK_ECC)DSO_bind_func(dso, "SDF_GenerateKeyWithEPK_ECC");
    sdfm->ImportKeyWithISK_ECC = (SDF_ImportKeyWithISK_ECC)DSO_bind_func(dso, "SDF_ImportKeyWithISK_ECC");
    sdfm->GenerateAgreementDataWithECC = (SDF_GenerateAgreementDataWithECC)DSO_bind_func(dso, "SDF_GenerateAgreementDataWithECC");
    sdfm->GenerateKeyWithECC = (SDF_GenerateKeyWithECC)DSO_bind_func(dso, "SDF_GenerateKeyWithECC");
    sdfm->GenerateAgreementDataAndKeyWithECC = (SDF_GenerateAgreementDataAndKeyWithECC)DSO_bind_func(dso, "SDF_GenerateAgreementDataAndKeyWithECC");
    sdfm->GenerateKeyWithKEK = (SDF_GenerateKeyWithKEK)DSO_bind_func(dso, "SDF_GenerateKeyWithKEK");
    sdfm->ImportKeyWithKEK = (SDF_ImportKeyWithKEK)DSO_bind_func(dso, "SDF_ImportKeyWithKEK");
    sdfm->DestroyKey = (SDF_DestroyKey)DSO_bind_func(dso, "SDF_DestroyKey");
    sdfm->ExternalPublicKeyOperation_RSA = (SDF_ExternalPublicKeyOperation_RSA)DSO_bind_func(dso, "SDF_ExternalPublicKeyOperation_RSA");
    sdfm->InternalPublicKeyOperation_RSA = (SDF_InternalPublicKeyOperation_RSA)DSO_bind_func(dso, "SDF_InternalPublicKeyOperation_RSA");
    sdfm->InternalPrivateKeyOperation_RSA = (SDF_InternalPrivateKeyOperation_RSA)DSO_bind_func(dso, "SDF_InternalPrivateKeyOperation_RSA");
    sdfm->ExternalVerify_ECC = (SDF_ExternalVerify_ECC)DSO_bind_func(dso, "SDF_ExternalVerify_ECC");
    sdfm->InternalSign_ECC = (SDF_InternalSign_ECC)DSO_bind_func(dso, "SDF_InternalSign_ECC");
    sdfm->InternalVerify_ECC = (SDF_InternalVerify_ECC)DSO_bind_func(dso, "SDF_InternalVerify_ECC");
    sdfm->ExternalEncrypt_ECC = (SDF_ExternalEncrypt_ECC)DSO_bind_func(dso, "SDF_ExternalEncrypt_ECC");
    sdfm->Encrypt = (SDF_Encrypt)DSO_bind_func(dso, "SDF_Encrypt");
    sdfm->Decrypt = (SDF_Decrypt)DSO_bind_func(dso, "SDF_Decrypt");
    sdfm->CalculateMAC = (SDF_CalculateMAC)DSO_bind_func(dso, "SDF_CalculateMAC");
    #ifdef SDF_VERSION_2023 
    sdfm->AuthEnc = (SDF_AuthEnc)DSO_bind_func(dso, "SDF_AuthEnc");
    sdfm->AuthDec = (SDF_AuthDec)DSO_bind_func(dso, "SDF_AuthDec");
    sdfm->EncryptInit = (SDF_EncryptInit)DSO_bind_func(dso, "SDF_EncryptInit");
    sdfm->EncryptUpdate = (SDF_EncryptUpdate)DSO_bind_func(dso, "SDF_EncryptUpdate");
    sdfm->EncryptFinal = (SDF_EncryptFinal)DSO_bind_func(dso, "SDF_EncryptFinal");
    sdfm->DecryptInit = (SDF_DecryptInit)DSO_bind_func(dso, "SDF_DecryptInit");
    sdfm->DecryptUpdate = (SDF_DecryptUpdate)DSO_bind_func(dso, "SDF_DecryptUpdate");
    sdfm->DecryptFinal = (SDF_DecryptFinal)DSO_bind_func(dso, "SDF_DecryptFinal");
    sdfm->CalculateMACInit = (SDF_CalculateMACInit)DSO_bind_func(dso, "SDF_CalculateMACInit");
    sdfm->CalculateMACUpdate = (SDF_CalculateMACUpdate)DSO_bind_func(dso, "SDF_CalculateMACUpdate");
    sdfm->CalculateMACFinal = (SDF_CalculateMACFinal)DSO_bind_func(dso, "SDF_CalculateMACFinal");
    sdfm->AuthEncInit = (SDF_AuthEncInit)DSO_bind_func(dso, "SDF_AuthEncInit");
    sdfm->AuthEncUpdate = (SDF_AuthEncUpdate)DSO_bind_func(dso, "SDF_AuthEncUpdate");
    sdfm->AuthEncFinal = (SDF_AuthEncFinal)DSO_bind_func(dso, "SDF_AuthEncFinal");
    sdfm->AuthDecInit = (SDF_AuthDecInit)DSO_bind_func(dso, "SDF_AuthDecInit");
    sdfm->AuthDecUpdate = (SDF_AuthDecUpdate)DSO_bind_func(dso, "SDF_AuthDecUpdate");
    sdfm->AuthDecFinal = (SDF_AuthDecFinal)DSO_bind_func(dso, "SDF_AuthDecFinal");
    sdfm->HMACInit = (SDF_HMACInit)DSO_bind_func(dso, "SDF_HMACInit");
    sdfm->HMACUpdate = (SDF_HMACUpdate)DSO_bind_func(dso, "SDF_HMACUpdate");
    sdfm->HMACFinal = (SDF_HMACFinal)DSO_bind_func(dso, "SDF_HMACFinal");
    #endif
    sdfm->HashInit = (SDF_HashInit)DSO_bind_func(dso, "SDF_HashInit");
    sdfm->HashUpdate = (SDF_HashUpdate)DSO_bind_func(dso, "SDF_HashUpdate");
    sdfm->HashFinal = (SDF_HashFinal)DSO_bind_func(dso, "SDF_HashFinal");
    sdfm->CreateFile = (SDF_CreateFile)DSO_bind_func(dso, "SDF_CreateFile");
    sdfm->ReadFile = (SDF_ReadFile)DSO_bind_func(dso, "SDF_ReadFile");
    sdfm->WriteFile = (SDF_WriteFile)DSO_bind_func(dso, "SDF_WriteFile");
    sdfm->DeleteFile = (SDF_DeleteFile)DSO_bind_func(dso, "SDF_DeleteFile");
    sdfm->GenerateKeyPair_ECC = (SDF_GenerateKeyPair_ECC)DSO_bind_func(dso, "SDF_GenerateKeyPair_ECC");
    #ifdef SDF_VERSION_2023
    sdfm->ExternalPrivateKeyOperation_RSA = (SDF_ExternalPrivateKeyOperation_RSA)DSO_bind_func(dso, "SDF_ExternalPrivateKeyOperation_RSA");
    sdfm->ExternalSign_ECC = (SDF_ExternalSign_ECC)DSO_bind_func(dso, "SDF_ExternalSign_ECC");
    sdfm->ExternalDecrypt_ECC = (SDF_ExternalDecrypt_ECC)DSO_bind_func(dso, "SDF_ExternalDecrypt_ECC");
    sdfm->ExternalSign_SM9 = (SDF_ExternalSign_SM9)DSO_bind_func(dso, "SDF_ExternalSign_SM9");
    sdfm->ExternalDecrypt_SM9 = (SDF_ExternalDecrypt_SM9)DSO_bind_func(dso, "SDF_ExternalDecrypt_SM9");
    sdfm->ExternalKeyEncrypt = (SDF_ExternalKeyEncrypt)DSO_bind_func(dso, "SDF_ExternalKeyEncrypt");
    sdfm->ExternalKeyDecrypt = (SDF_ExternalKeyDecrypt)DSO_bind_func(dso, "SDF_ExternalKeyDecrypt");
    sdfm->ExternalKeyEncryptInit = (SDF_ExternalKeyEncryptInit)DSO_bind_func(dso, "SDF_ExternalKeyEncryptInit");
    sdfm->ExternalKeyDecryptInit = (SDF_ExternalKeyDecryptInit)DSO_bind_func(dso, "SDF_ExternalKeyDecryptInit");
    sdfm->ExternalKeyHMACInit = (SDF_ExternalKeyHMACInit)DSO_bind_func(dso, "SDF_ExternalKeyHMACInit");
    #endif
    return 0;
}