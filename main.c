#include <stdio.h>
#include <dlfcn.h>
// #include "testcases.h"
#include "sdf_bind.h"
#include <stdlib.h>
#include <string.h>
#include "Cli-function.h"
// #include "swsds.h"
// Global counters (referenced via extern in testcases.h)
#include<getopt.h>
#include "AlgMark.h"
#define DEBUG
#ifdef DEBUG
    #define debug_printf(...) printf(__VA_ARGS__)
#else
    #define debug_printf(...)
#endif
int pass = 0;
int fail = 0;
int notsupport = 0;
int info_device = 0;
int get_random = 0;
unsigned int KeyIndex = 0;
int export_encpubkey_ecc = 0;
int export_encpubkey_rsa = 0;
int export_signpubkey_ecc = 0;
int export_signpubkey_rsa = 0;

int generatekeywith_kek = 0;
int generatekeywith_ipk_rsa = 0;
int generatekeywith_epk_rsa = 0;
int generatekeywith_ipk_ecc = 0;
int generatekeywith_epk_ecc = 0;

int importkeywith_kek = 0;
int importkeywith_isk_rsa = 0;
int importkeywith_isk_ecc = 0;

int extrsatest = 0;
int intrsatest = 0;
int inteccsigntest = 0;
int exteccsigntest = 0;
int exteccenctest = 0;

int symencdectest = 0; 
int calculatemac = 0;
#ifdef DEBUG
void print_help(void) {
    printf("SDF命令行工具 - 基于GM/T 0018-2012标准\n\n");
    printf("用法: sdf-tool [选项]\n\n");
    
    printf("设备管理选项:\n");
    printf("  -i, --device-info             显示设备信息\n");
    printf("  -r, --random LENGTH           生成指定长度的随机数\n");
    
    printf("\n非对称公钥导出选项:\n");
    printf("  --export-encpubkey-ecc INDEX  导出ECC加密公钥\n");
    printf("  --export-signpubkey-ecc INDEX 导出ECC签名公钥\n");
    printf("  --export-encpubkey-rsa INDEX  导出RSA加密公钥\n");
    printf("  --export-signpubkey-rsa INDEX 导出RSA签名公钥\n");
    
    printf("\n会话密钥生成选项:\n");
    printf("  --generatekeywith-kek INDEX   使用KEK产生会话密钥\n");
    printf("  --generatekeywith-ipk-rsa INDEX 使用RSA内部公钥产生会话密钥\n");
    printf("  --generatekeywith-epk-rsa INDEX 使用RSA外部公钥产生会话密钥\n");
    printf("  --generatekeywith-ipk-ecc INDEX 使用ECC内部公钥产生会话密钥\n");
    printf("  --generatekeywith-epk-ecc INDEX 使用ECC外部公钥产生会话密钥\n");
    
    printf("\n会话密钥导入选项:\n");
    printf("  --importkeywith-kek INDEX     使用KEK导入会话密钥\n");
    printf("  --importkeywith-isk-rsa INDEX 使用RSA内部私钥导入会话密钥\n");
    printf("  --importkeywith-isk-ecc INDEX 使用ECC内部私钥导入会话密钥\n");
    
    printf("\n密码运算测试选项:\n");
    printf("  --extrsatest                  外部RSA运算测试\n");
    printf("  --intrsatest                  内部RSA运算测试\n");
    printf("  --inteccsigntest              内部ECC签名测试\n");
    printf("  --exteccsigntest              外部ECC签名测试\n");
    printf("  --exteccenctest               外部ECC加密测试\n");
    printf("  --symencdectest               对称加密解密测试\n");
    printf("  --calculatemac                计算MAC测试\n");
    
    printf("\n通用选项:\n");
    printf("  -h, --help                    显示此帮助信息\n");
    printf("  -v, --version                 显示版本信息\n");
    printf("\n说明:\n");
    printf("  INDEX参数为密钥索引号，范围为1-100\n");
    printf("  LENGTH参数为随机数长度，单位为字节\n");
}
#else
void print_help(void) {
    printf("SDF Command Line Tool - Based on GM/T 0018-2012 Standard\n\n");
    printf("Usage: sdf-tool [OPTIONS]\n\n");
    
    printf("Device Management Options:\n");
    printf("  -i, --device-info             Display device information\n");
    printf("  -r, --random LENGTH           Generate random number of specified length\n");
    
    printf("\nAsymmetric Public Key Export Options:\n");
    printf("  --export-encpubkey-ecc INDEX  Export ECC encryption public key\n");
    printf("  --export-signpubkey-ecc INDEX Export ECC signature public key\n");
    printf("  --export-encpubkey-rsa INDEX  Export RSA encryption public key\n");
    printf("  --export-signpubkey-rsa INDEX Export RSA signature public key\n");
    
    printf("\nSession Key Generation Options:\n");
    printf("  --generatekeywith-kek INDEX   Generate session key using KEK\n");
    printf("  --generatekeywith-ipk-rsa INDEX Generate session key using RSA internal public key\n");
    printf("  --generatekeywith-epk-rsa INDEX Generate session key using RSA external public key\n");
    printf("  --generatekeywith-ipk-ecc INDEX Generate session key using ECC internal public key\n");
    printf("  --generatekeywith-epk-ecc INDEX Generate session key using ECC external public key\n");
    
    printf("\nSession Key Import Options:\n");
    printf("  --importkeywith-kek INDEX     Import session key using KEK\n");
    printf("  --importkeywith-isk-rsa INDEX Import session key using RSA internal private key\n");
    printf("  --importkeywith-isk-ecc INDEX Import session key using ECC internal private key\n");
    
    printf("\nCryptographic Operation Test Options:\n");
    printf("  --extrsatest                  External RSA operation test\n");
    printf("  --intrsatest                  Internal RSA operation test\n");
    printf("  --inteccsigntest              Internal ECC signature test\n");
    printf("  --exteccsigntest              External ECC signature test\n");
    printf("  --exteccenctest               External ECC encryption test\n");
    printf("  --symencdectest               Symmetric encryption/decryption test\n");
    printf("  --calculatemac                Calculate MAC test\n");
    
    printf("\nGeneral Options:\n");
    printf("  -h, --help                    Display this help message\n");
    printf("  -v, --version                 Display version information\n");
    printf("\nNotes:\n");
    printf("  INDEX parameter is key index number, range 1-100\n");
    printf("  LENGTH parameter is random number length in bytes\n");
}
#endif
void printAlgInfo(){
    void *hDevice = NULL;
    void *hSession = NULL;
    int ret = -1;
    // #define SGD_SM4_CBC		(SGD_SM4|SGD_CBC)
    // #define SGD_SM4			0x00000400
    // #define SGD_CBC			0x02
        DEVICEINFO stDeviceInfo;
        memset(&stDeviceInfo, 0, sizeof(DEVICEINFO));
        ret = OpenDevice(&hDevice); if(ret != SDR_OK){ printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
        ret = OpenSession(hDevice, &hSession); if(ret != SDR_OK){ printf("OpenSession failed: %s\n", SDF_GetErrorString(ret)); goto cleanup; }
 
        ret = GetDeviceInfo(hSession, &stDeviceInfo);
        if (ret != SDR_OK)
        {
            printf("获取设备信息错误，错误码[0x%08x]\n", ret);
        }

        int i = 1;

        if (stDeviceInfo.SymAlgAbility & SGD_SM1_ECB & SGD_SYMM_ALG_MASK)
        {
            printf("  %d | SGD_SM1_ECB\n\n", i++);
        }
        if (stDeviceInfo.SymAlgAbility & SGD_SSF33_ECB & SGD_SYMM_ALG_MASK)
        {
            printf("  %d | SGD_SSF33_ECB\n\n", i++);
        }
        if (stDeviceInfo.SymAlgAbility & SGD_AES_ECB & SGD_SYMM_ALG_MASK)
        {
            printf("  %d | SGD_AES_ECB\n\n", i++);
        }
        if (stDeviceInfo.SymAlgAbility & SGD_DES_ECB & SGD_SYMM_ALG_MASK)
        {
            printf("  %d | SGD_DES_ECB\n\n", i++);
        }
        if (stDeviceInfo.SymAlgAbility & SGD_3DES_ECB & SGD_SYMM_ALG_MASK)
        {
            printf("  %d | SGD_3DES_ECB\n\n", i++);
        }
        if (stDeviceInfo.SymAlgAbility & SGD_SM4_ECB & SGD_SYMM_ALG_MASK)
        {
            printf("  %d | SGD_SM4_ECB\n\n", i++);
        }
        if (stDeviceInfo.SymAlgAbility & SGD_SM7_ECB & SGD_SYMM_ALG_MASK)
        {
            printf("  %d | SGD_SM7_ECB\n\n", i++);
        }
        if (stDeviceInfo.SymAlgAbility & SGD_SM6_ECB & SGD_SYMM_ALG_MASK)
        {
            printf("  %d | SGD_SM6_ECB\n\n", i++);
        }
cleanup:
    if(hSession)free(hSession);
    if(hDevice)free(hDevice);
}
void print_version(){
    printf("sdf version1.0\n\n");

    printAlgInfo();
}

int main(int argc,char *argv[]){
    void *handle = dlopen("./libswsds.so", RTLD_LAZY);
    if (!handle) {
        printf("dlopen error: %s\n", dlerror());
        return 1;
    }
    sdf_bind_init(handle);
    int opt;
    int option_index;

    static struct option long_options[] = {
        {"device-info", no_argument, NULL, 'i'},
        {"random",      required_argument,  NULL, 'r'},


        // 导出非对称公钥
        {"export-encpubkey-ecc",required_argument,NULL,1},
        {"export-signpubkey-ecc",required_argument,NULL,2},

        {"export-encpubkey-rsa",required_argument,NULL,3},
        {"export-signpubkey-rsa",required_argument,NULL,4},

        // 产生会话密钥
        {"generatekeywith-kek",required_argument,NULL,5},
        {"generatekeywith-ipk-rsa",required_argument,NULL,6},
        {"generatekeywith-epk-rsa",required_argument,NULL,7},
        {"generatekeywith-ipk-ecc",required_argument,NULL,8},
        {"generatekeywith-epk-ecc",required_argument,NULL,9},

        // 导入会话密钥
        {"importkeywith-kek",required_argument,NULL,10},
        {"importkeywith-isk-rsa",required_argument,NULL,11},
        {"importkeywith-isk-ecc",required_argument,NULL,12},

        // 非对称运算
        {"extrsatest",no_argument,NULL,13},
        {"intrsatest",no_argument,NULL,14},
        {"inteccsigntest",no_argument,NULL,15},
        {"exteccsigntest",no_argument,NULL,16},
        {"exteccenctest",no_argument,NULL,17},

        {"symencdectest",no_argument,NULL,18},
        {"calculatemac",no_argument,NULL,19},
        {"help",no_argument,NULL,'h'},
        {"version",no_argument,NULL,'v'},
        // {},
        {0,0,0,0}
    };
    const char *optstring = "ir:hv";
    if (argc == 1) {
        print_help();
        return 0;
    }
    while((opt = getopt_long(argc,argv,optstring,long_options,&option_index)) != -1){
        switch (opt)
        {
            case 'i':
                info_device = 1;
                break;
            case 'r':
                get_random = 1;
                break;
            case 'h':
                print_help();
                break;
            case 'v':
                print_version();
                break;
            case 1:
                export_encpubkey_ecc = 1;
                KeyIndex = atoi(optarg);
                break;
            case 2:
                export_signpubkey_ecc = 1;
                KeyIndex = atoi(optarg);
                break;
            case 3:
                export_encpubkey_rsa = 1;
                KeyIndex = atoi(optarg);
                break;
            case 4:
                export_signpubkey_rsa = 1;
                KeyIndex = atoi(optarg);
                break;
            case 5:
                generatekeywith_kek = 1;
                KeyIndex = atoi(optarg);
                break;
            case 6:
                generatekeywith_ipk_rsa = 1;
                KeyIndex = atoi(optarg);
                break;
            case 7:
                generatekeywith_epk_rsa = 1;
                KeyIndex = atoi(optarg);
                break;
            case 8:
                generatekeywith_ipk_ecc = 1;
                KeyIndex = atoi(optarg);
                break;
            case 9:
                generatekeywith_epk_ecc = 1;
                KeyIndex = atoi(optarg);
                break;
            case 10:
                importkeywith_kek = 1;
                KeyIndex = atoi(optarg);
                break;
            case 11:
                importkeywith_isk_rsa = 1;
                KeyIndex = atoi(optarg);
                break;
            case 12:
                importkeywith_isk_ecc = 1;
                KeyIndex = atoi(optarg);
                break;
            case 13:
                extrsatest = 1;
                break;
            case 14:
                intrsatest = 1;
                break;
            case 15:
                inteccsigntest = 1;
                break;
            case 16:
                exteccsigntest = 1;
                break;
            case 17:
                exteccenctest = 1;
                break;
            case 18:
                symencdectest = 1;
                break;
            case 19:
                calculatemac = 1;
                break;
            default:
                exit(1);
        }
    }
    if(info_device){
        Test_GetDeviceInfo();
    }
    if(get_random){
        Test_GenerateRandom();
    }
    // 导出非对称密钥
    if(export_encpubkey_ecc){
        Test_ExportEncPublicKey_ECC(KeyIndex);
    }
    if(export_signpubkey_ecc){
        Test_ExportSignPublicKey_ECC(KeyIndex);
    }
    if(export_encpubkey_rsa){
        Test_ExportEncPublic_RSA(KeyIndex);
    }
    if(export_signpubkey_rsa){
        Test_ExportSignPublicKey_RSA(KeyIndex);
    }
    // 产生会话密钥
    if(generatekeywith_kek){
        Test_GenerateKeyWithKEK(KeyIndex);
    }
    if(generatekeywith_ipk_rsa){
        Test_GenerateKeyWithIPK_RSA(KeyIndex);
    }
    if(generatekeywith_epk_rsa){
        Test_GenerateKeyWithEPK_RSA(KeyIndex);
    }
    if(generatekeywith_ipk_ecc){
        Test_GenerateKeyWithIPK_ECC(KeyIndex);
    }
    if(generatekeywith_epk_ecc){
        Test_GenerateKeyWithEPK_ECC(KeyIndex);
    }

    // 导入会话密钥
    if(importkeywith_kek){
        Test_ImportKeyWithKEK(KeyIndex);
    }
    if(importkeywith_isk_rsa){
        Test_ImportKeyWithISK_RSA(KeyIndex);
    }
    if(importkeywith_isk_ecc){
        Test_ImportKeyWithISK_ECC(KeyIndex);
    }

    if(extrsatest){
        ExtRSAOptTest();
        // Test_ExternalPrivateKeyOperation_RSA();
    }
    if(intrsatest){
        IntRSAOptTest();
    }
    if(inteccsigntest){
        IntECCSignTest();
    }
    if(exteccsigntest){
        ExtECCSignTest();
    }
    if(exteccenctest){
        ExtECCOptTest();
    }
    if(symencdectest){
        SymmEncDecTest();
    }
    if(calculatemac){
        Test_CalculateMAC();
    }

    return 0;
}