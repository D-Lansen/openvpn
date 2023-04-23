#include <stdio.h>
extern "C"
int lzo_test(void);

extern "C"
int lz4_test(void);

extern "C"
int test(){
    int lzo = lzo_test();
    printf("lzo: %d\r\n",lzo);

    int lz4 = lz4_test();
    printf("lz4: %d\r\n",lz4);
    return 0;
}


extern
const char* test_print(){
    return "lichen4";
}
