#include <stdio.h>
#include <dlfcn.h>
// #include "testcases.h"
#include "sdf_bind.h"
// #include "swsds.h"
// Global counters (referenced via extern in testcases.h)
int pass = 0;
int fail = 0;
int notsupport = 0;
int main(){
    void *handle = dlopen("./libswsds.so", RTLD_LAZY);
    if (!handle) {
        printf("dlopen error: %s\n", dlerror());
        return 1;
    }
    sdf_bind_init(handle);
    // Test_all();
    // printf("\nSummary:\n\033[32m[Pass]=%d\033[0m\n\033[31m[Fail]=%d\033[0m\n\033[33m[NotSupport]=%d\033[0m \n", pass, fail, notsupport);
    // dlclose(handle);
    // if(fail==0) {
    //     printf("All tests passed or not supported.\n");
    // }
    return 0;
}