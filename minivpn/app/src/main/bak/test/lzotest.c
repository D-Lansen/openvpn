#include <stdio.h>
#include <stdlib.h>

#include "../lzo/include/lzo/lzoconf.h"
#include "../lzo/include/lzo/lzo1x.h"


#define lzo_malloc(a)         (malloc(a))
#define lzo_free(a)           (free(a))

static lzo_voidp xmalloc(lzo_uint len)
{
    lzo_voidp p;
    lzo_uint align = (lzo_uint) sizeof(lzo_align_t);

    p = (lzo_voidp) lzo_malloc(len > 0 ? len : 1);
    if (p == NULL) {
        printf("%s: out of memory\n", "");
        exit(1);
    }
    if (__lzo_align_gap(p, align) != 0) {
        printf("%s: C library problem: malloc() returned misaligned pointer!\n", "");
        lzo_free(p);
        exit(1);
    }
    return p;
}

#ifndef IN_LEN
#define IN_LEN      (128*1024L)
#endif

#ifndef OUT_LEN
#define OUT_LEN     (IN_LEN + IN_LEN / 16 + 64 + 3)
#endif

int lzo_test() {
    printf("\nlzo library (v%s, %s).\n",
           lzo_version_string(), lzo_version_date());

    /*
    * Step 1: initialize the LZO library
    */
    if (lzo_init() != LZO_E_OK) {
        printf("internal error - lzo_init() failed !!!\n");
        printf("(this usually indicates a compiler bug - try recompiling\nwithout optimizations, and enable '-DLZO_DEBUG' for diagnostics)\n");
        return 4;
    }

    /*
    * Step 2: allocate blocks and the work-memory
    */
    lzo_bytep in = (lzo_bytep) xmalloc(IN_LEN);
    lzo_bytep out = (lzo_bytep) xmalloc(OUT_LEN);
    lzo_voidp wrkmem = (lzo_voidp) xmalloc(LZO1X_1_MEM_COMPRESS);
    if (in == NULL || out == NULL || wrkmem == NULL) {
        printf("out of memory\n");
        return 3;
    }

    /*
     * Step 3: prepare the input block that will get compressed.
     *         We just fill it with zeros in this example program,
     *         but you would use your real-world data here.
     */
    lzo_uint out_len;
    lzo_uint new_len;
    lzo_uint in_len;
    in_len = IN_LEN;
    lzo_memset(in,0,in_len);

    /*
     * Step 4: compress from 'in' to 'out' with LZO1X-1
     */
    int r = lzo1x_1_compress(in, in_len, out, &out_len, wrkmem);
    if (r == LZO_E_OK) {
        printf("compressed %lu bytes into %lu bytes\n",
               (unsigned long) in_len, (unsigned long) out_len);
    }
    else {
        /* this should NEVER happen */
        printf("internal error - compression failed: %d\n", r);
        return 2;
    }
    /* check for an incompressible block */
    if (out_len >= in_len) {
        printf("This block contains incompressible data.\n");
        return 0;
    }

    /*
     * Step 5: decompress again, now going from 'out' to 'in'
     */
    new_len = in_len;
    r = lzo1x_decompress(out, out_len, in, &new_len, NULL);
    if (r == LZO_E_OK) {
        printf("decompressed %lu bytes back into %lu bytes\n",
               (unsigned long) out_len, (unsigned long) in_len);
    }
    else {
        /* this should NEVER happen */
        printf("internal error - decompression failed: %d\n", r);
        return 1;
    }

    lzo_free(wrkmem);
    lzo_free(out);
    lzo_free(in);
    printf("Simple compression test passed.\n");
    return 0;
}