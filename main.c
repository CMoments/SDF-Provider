#include <stdio.h>
#include <dlfcn.h>
// #include "testcases.h"
#include "sdf_bind.h"
#include <stdlib.h>
#include <string.h>
// #include "swsds.h"
// Global counters (referenced via extern in testcases.h)
#include<getopt.h>
int Test_GetDeviceInfo(){
    int ret = -1;
    void *hDevice = NULL;
    void *hSession = NULL;
    ret = OpenDevice(&hDevice);
    if (ret != SDR_OK){
        printf("OpenDevice failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    ret = OpenSession(hDevice, &hSession);
    if (ret != SDR_OK){
        printf("OpenSession failed: %s\n", SDF_GetErrorString(ret));
        goto cleanup;
    }
    DEVICEINFO deviceInfo;
    ret = GetDeviceInfo(hSession, &deviceInfo);
    if (ret == 0) {
        printf("\n========== GetDeviceInfo: %s ==========\n", SDF_GetErrorString(ret));
        printf("IssuerName: %s\n", deviceInfo.IssuerName);
        printf("SerialNumber: %s\n", deviceInfo.SerialNumber);
        printf("FirmwareVersion: %s\n", deviceInfo.FirmwareVersion);
        printf("DeviceVersion: %08x\n", deviceInfo.DeviceVersion);
        printf("StandardVersion: %d\n", deviceInfo.StandardVersion);
        printf("AsymAlgAbility: [%08x, %08x]\n", deviceInfo.AsymAlgAbility[0], deviceInfo.AsymAlgAbility[1]);
        printf("SymAlgAbility: %08x\n", deviceInfo.SymAlgAbility);
        printf("HashAlgAbility: %08x\n", deviceInfo.HashAlgAbility);
        printf("BufferSize: %d\n", deviceInfo.BufferSize);
        printf("===============================================\n");
    } else {
        printf("Failed GetDeviceInfo: %s\n", SDF_GetErrorString(ret));
    }
cleanup:
    if(hSession){
        CloseSession(hSession);
    }
    if(hDevice){
        CloseDevice(hDevice);
    }
    return ret;
}
int pass = 0;
int fail = 0;
int notsupport = 0;
int info_device = 0;
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
        // {},
        // {},
        // {},
        {0,0,0,0}
    };

    while((opt = getopt_long(argc,argv,"i",long_options,&option_index)) != -1){
        switch (opt)
        {
            case 'i':
                info_device = 1;
                break;
            default:
                exit(1);
        }
    }
    if(info_device){
        Test_GetDeviceInfo();
    }
    return 0;
}