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
int pass = 0;
int fail = 0;
int notsupport = 0;
int info_device = 0;
int get_random = 0;
int export_pubkey_ecc = 0;
unsigned int KeyIndex = 0;
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


        {"export-encpubkey-ecc",required_argument,NULL,'e'},
        {"export-signpubkey-ecc",required_argument,NULL,'e'},

        {"export-encpubkey-rsa",required_argument,NULL,'e'},
        {"export-signpubkey-rsa",required_argument,NULL,'e'},


        // {},
        // {},
        {0,0,0,0}
    };

    while((opt = getopt_long(argc,argv,"ir:e:",long_options,&option_index)) != -1){
        switch (opt)
        {
            case 'i':
                info_device = 1;
                break;
            case 'r':
                get_random = 1;
                break;
            case 'e':
                export_pubkey_ecc = 1;
                KeyIndex = atoi(optarg);
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
    if(export_pubkey_ecc){
        Test_ExportEncPublicKey_ECC(KeyIndex);
    }
    return 0;
}