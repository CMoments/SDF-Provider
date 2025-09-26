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

void print_help(void) {
    printf("SDF命令行工具 - 基于GM/T 0018-2012标准\n\n");
    printf("用法: sdf-tool [选项]\n\n");
    printf("设备管理选项:\n");
    printf("  -i, --device-info             显示设备信息\n");
    printf("  -r, --random LENGTH           生成指定长度的随机数\n");
    // printf("\n密钥管理选项:\n");
    // printf("  -e, --export-pubkey-ecc INDEX 导出ECC公钥\n");
    // printf("  -E, --export-pubkey-rsa INDEX 导出RSA公钥\n");
    // printf("  -g, --generate-session        生成会话密钥\n");
    // printf("\n密码运算选项:\n");
    // printf("  -s, --sign-ecc INDEX          ECC签名\n");
    // printf("  -v, --verify-ecc              ECC验证\n");
    // printf("\n通用参数:\n");
    // printf("  -D, --device PATH             设备路径(默认: /dev/sdf0)\n");
    // printf("  -k, --key-index INDEX         密钥索引(默认: 1)\n");
    // printf("  -f, --data FILE               数据文件\n");
    // printf("  -S, --sig FILE                签名文件\n");
    // printf("  -p, --pubkey FILE             公钥文件\n");
    // printf("  -o, --output FILE             输出文件\n");
    // printf("  -l, --length LENGTH           数据长度\n");
    printf("  -h, --help                    显示此帮助信息\n");
    printf("  -v, --version                 显示版本信息\n");
}
void print_version(){
    printf("sdf version1.0\n");
}
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


        {"help",no_argument,NULL,'h'},
        {"version",no_argument,NULL,'v'},
        // {},
        {0,0,0,0}
    };
    const char *optstring = "ir:hv";
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

    }
    if(exteccenctest){

    }

    return 0;
}