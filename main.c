#include <stdio.h>
#include <dlfcn.h>
// #include "testcases.h"
#include "sdf_bind.h"
#include <stdlib.h>
#include <string.h>
// #include "swsds.h"
// Global counters (referenced via extern in testcases.h)
#include<getopt.h>

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
        DEVICEINFO *device = malloc(sizeof(DEVICEINFO));
        void *hDevice = NULL;
        OpenDevice(&hDevice);
        GetDeviceInfo(hDevice,device);
        printf("设备厂商: %s\n",device->IssuerName);
    }
    return 0;
}