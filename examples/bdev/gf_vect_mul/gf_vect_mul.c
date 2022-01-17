#include "isa-l/include/raid.h"
#include "isa-l/include/gf_vect_mul.h"
#include "isa-l/include/erasure_code.h"
#include "spdk/stdinc.h"
#include "spdk/string.h"
#include<stdio.h>
#include<stdint.h>
#include<string.h>
#include<stdlib.h>
#include<limits.h>

#define TEST_SOURCES 14
#define TEST_LEN     4096
#define TEST_MEM ((TEST_SOURCES + 2)*(TEST_LEN))
#ifndef TEST_SEED
# define TEST_SEED 0x1234
#endif

// Generates pseudo-random data

void rand_buffer(unsigned char *buf, long buffer_size)
{
    long i;
    for (i = 0; i < buffer_size; i++)
        buf[i] = rand();
}

int dump(unsigned char *buf, int len)
{
    int i;
    for (i = 0; i < len;) {
        printf(" %2x", buf[i++]);
        if (i % 16 == 0)
            printf("\n");
    }
    printf("\n");
    return 0;
}

void xor_buf(void *restrict to, void *restrict from, size_t size)
{
    int ret;
    void *vects[3] = { from, to, to };

    ret = xor_gen(3, size, vects);
    if (ret) {
        printf("xor_gen failed\n");
    }
}

int
main(int argc, char **argv)
{
    unsigned char gf_const_tbl_arr[255][32];
    int i, j, k, ret, fail = 0;
    void *buffs[TEST_SOURCES + 2];	// Pointers to src and dest
    void *buffs2[TEST_SOURCES + 2];
    void *tmp_buf[TEST_SOURCES + 2];

    for (i = 0; i < 255; i++) {
        unsigned char c = 1;
        for (j = 0; j < i; j++) {
            c = gf_mul(c, 2);
        }
        gf_vect_mul_init(c, gf_const_tbl_arr[i]);
    }

    printf("Test pq_gen_test\n");

    srand(TEST_SEED);

    // Allocate the arrays
    for (i = 0; i < TEST_SOURCES + 2; i++) {
        void *buf;
        ret = posix_memalign(&buf, 32, TEST_LEN);
        if (ret) {
            printf("alloc error: Fail\n");
            return 1;
        }
        buffs[i] = buf;
        ret = posix_memalign(&buf, 32, TEST_LEN);
        if (ret) {
            printf("alloc error: Fail\n");
            return 1;
        }
        buffs2[i] = buf;
        ret = posix_memalign(&buf, 32, TEST_LEN);
        if (ret) {
            printf("alloc error: Fail\n");
            return 1;
        }
        tmp_buf[i] = buf;
    }

    // Test of all zeros
    for (i = 0; i < TEST_SOURCES + 2; i++) {
        memset(buffs[i], 0, TEST_LEN);
        memset(buffs2[i], 0, TEST_LEN);
        memset(tmp_buf[i], 0, TEST_LEN);
    }
    pq_gen(TEST_SOURCES + 2, TEST_LEN, buffs);

    memcpy(buffs2[TEST_SOURCES], buffs[0], TEST_LEN);
    for (i = 1; i < TEST_SOURCES; i++) {
        xor_buf(buffs2[TEST_SOURCES], buffs[i], TEST_LEN);
    }
    for (i = 0; i < TEST_SOURCES; i++) {
        gf_vect_mul(TEST_LEN, gf_const_tbl_arr[i], buffs[i], buffs2[i]);
    }
    memcpy(buffs2[TEST_SOURCES + 1], buffs2[0], TEST_LEN);
    for (i = 1; i < TEST_SOURCES; i++) {
        xor_buf(buffs2[TEST_SOURCES + 1], buffs2[i], TEST_LEN);
    }

    for (i = 0; i < TEST_LEN; i++) {
        if (((char *)buffs[TEST_SOURCES])[i] != 0) {
            fail++;
        }
        if (((char *)buffs[TEST_SOURCES])[i] != ((char *)buffs2[TEST_SOURCES])[i]) {
            fail++;
        }
    }

    for (i = 0; i < TEST_LEN; i++) {
        if (((char *)buffs[TEST_SOURCES + 1])[i] != 0) {
            fail++;
        }
        if (((char *)buffs[TEST_SOURCES + 1])[i] != ((char *)buffs2[TEST_SOURCES + 1])[i]) {
            fail++;
        }
    }

    if (fail > 0) {
        printf("fail zero test %d\n", fail);
        return 1;
    } else
        putchar('.');

    fflush(0);

    // Test rand
    for (i = 0; i < TEST_SOURCES; i++) {
        rand_buffer(buffs[i], TEST_LEN);
    }
    memset(buffs[TEST_SOURCES], 0, TEST_LEN);
    memset(buffs[TEST_SOURCES + 1], 0, TEST_LEN);

    for (i = 0; i < TEST_SOURCES + 2; i++) {
        memset(buffs2[i], 0, TEST_LEN);
    }

    ret = pq_gen(TEST_SOURCES + 2, TEST_LEN, buffs);

    for (i = 0; i < TEST_SOURCES; i++) {
        xor_buf(buffs2[TEST_SOURCES], buffs[i], TEST_LEN);
    }
    for (i = 0; i < TEST_SOURCES; i++) {
        gf_vect_mul(TEST_LEN, gf_const_tbl_arr[i], buffs[i], buffs2[i]);
    }
    for (i = 0; i < TEST_SOURCES; i++) {
        xor_buf(buffs2[TEST_SOURCES + 1], buffs2[i], TEST_LEN);
    }

    for (i = 0; i < TEST_SOURCES; i++) {
        memcpy(buffs2[i], buffs[i], TEST_LEN);
    }

    fail |= pq_check_base(TEST_SOURCES + 2, TEST_LEN, buffs);
    fail |= pq_check_base(TEST_SOURCES + 2, TEST_LEN, buffs2);

    if (fail > 0) {
        int t;
        printf(" Fail rand test1 fail=%d, ret=%d\n", fail, ret);
        for (t = 0; t < TEST_SOURCES + 2; t++)
            dump(buffs2[t], 15);

        printf(" reference function p,q\n");
        pq_gen_base(TEST_SOURCES + 2, TEST_LEN, buffs);
        for (t = TEST_SOURCES; t < TEST_SOURCES + 2; t++)
            dump(buffs[t], 15);

        return 1;
    } else
        putchar('.');

    fflush(0);

    // Test blocks
    for (i = 0; i < TEST_SOURCES; i++) {
        rand_buffer(buffs[i], TEST_LEN);
    }
    memset(buffs[TEST_SOURCES], 0, TEST_LEN);
    memset(buffs[TEST_SOURCES + 1], 0, TEST_LEN);

    for (i = 0; i < TEST_SOURCES + 2; i++) {
        memset(buffs2[i], 0, TEST_LEN);
    }

    ret = pq_gen(TEST_SOURCES + 2, TEST_LEN, buffs);

    for (i = 0; i < TEST_SOURCES; i++) {
        for (j = 0; j < TEST_LEN; j += 512) {
            xor_buf(&buffs2[TEST_SOURCES][j], &buffs[i][j], 512);
        }
    }
    for (i = 0; i < TEST_SOURCES; i++) {
        for (j = 0; j < TEST_LEN; j += 512) {
            gf_vect_mul(512, gf_const_tbl_arr[i], &buffs[i][j], &buffs2[i][j]);
        }
    }
    for (i = 0; i < TEST_SOURCES; i++) {
        for (j = 0; j < TEST_LEN; j += 512) {
            xor_buf(&buffs2[TEST_SOURCES + 1][j], &buffs2[i][j], 512);
        }
    }

    for (i = 0; i < TEST_SOURCES; i++) {
        memcpy(buffs2[i], buffs[i], TEST_LEN);
    }

    fail |= pq_check_base(TEST_SOURCES + 2, TEST_LEN, buffs);
    fail |= pq_check_base(TEST_SOURCES + 2, TEST_LEN, buffs2);

    if (fail > 0) {
        int t;
        printf(" Fail rand test1 fail=%d, ret=%d\n", fail, ret);
        for (t = 0; t < TEST_SOURCES + 2; t++)
            dump(buffs2[t], 15);

        printf(" reference function p,q\n");
        pq_gen_base(TEST_SOURCES + 2, TEST_LEN, buffs);
        for (t = TEST_SOURCES; t < TEST_SOURCES + 2; t++)
            dump(buffs[t], 15);

        return 1;
    } else
        putchar('.');

    fflush(0);


    // Test D+P
    for (i = 0; i < TEST_SOURCES; i++) {
        rand_buffer(buffs[i], TEST_LEN);
    }
    memset(buffs[TEST_SOURCES], 0, TEST_LEN);
    memset(buffs[TEST_SOURCES + 1], 0, TEST_LEN);

    for (i = 0; i < TEST_SOURCES + 2; i++) {
        memset(buffs2[i], 0, TEST_LEN);
    }

    ret = pq_gen(TEST_SOURCES + 2, TEST_LEN, buffs);

    for (i = 0; i < TEST_SOURCES; i++) {
        gf_vect_mul(TEST_LEN, gf_const_tbl_arr[i], buffs[i], buffs2[i]);
    }

    for (i = 0; i < TEST_SOURCES; i++) {
        if (i == 3) {
            continue;
        }
        xor_buf(buffs2[TEST_SOURCES + 1], buffs2[i], TEST_LEN);
    }
    xor_buf(buffs2[TEST_SOURCES + 1], buffs[TEST_SOURCES + 1], TEST_LEN);

    gf_vect_mul(TEST_LEN, gf_const_tbl_arr[255-3], buffs2[TEST_SOURCES + 1], buffs2[3]);

    for (i = 0; i < TEST_LEN; i++) {
        if (((char *)buffs[3])[i] != ((char *)buffs2[3])[i]) {
            fail++;
        }
    }

    if (fail > 0) {
        printf("fail d+p test %d\n", fail);
        return 1;
    } else
        putchar('.');

    fflush(0);

    // Test D+D
    for (i = 0; i < TEST_SOURCES; i++) {
        rand_buffer(buffs[i], TEST_LEN);
    }
    memset(buffs[TEST_SOURCES], 0, TEST_LEN);
    memset(buffs[TEST_SOURCES + 1], 0, TEST_LEN);

    for (i = 0; i < TEST_SOURCES + 2; i++) {
        memset(buffs2[i], 0, TEST_LEN);
    }

    ret = pq_gen(TEST_SOURCES + 2, TEST_LEN, buffs);

    for (i = 0; i < TEST_SOURCES; i++) {
        gf_vect_mul(TEST_LEN, gf_const_tbl_arr[i], buffs[i], buffs2[i]);
    }

    for (i = 0; i < TEST_SOURCES; i++) {
        if (i == 3 || i == 8) {
            continue;
        }
        xor_buf(buffs2[TEST_SOURCES], buffs[i], TEST_LEN);
        xor_buf(buffs2[TEST_SOURCES + 1], buffs2[i], TEST_LEN);
    }
    xor_buf(buffs2[TEST_SOURCES], buffs[TEST_SOURCES], TEST_LEN);
    xor_buf(buffs2[TEST_SOURCES + 1], buffs[TEST_SOURCES + 1], TEST_LEN);

    unsigned char g_y_minus_x = 1;
    unsigned char g_minus_x = 1;
    for (i = 0; i < 8 - 3; i++) {
        g_y_minus_x = gf_mul(g_y_minus_x, 2);
    }
    for (i = 0; i < 255 - 3; i++) {
        g_minus_x = gf_mul(g_minus_x, 2);
    }
    unsigned char a = gf_mul(g_y_minus_x, gf_inv(g_y_minus_x ^ 1));
    unsigned char b = gf_mul(g_minus_x, gf_inv(g_y_minus_x ^ 1));
    unsigned char gf_const_tbl_a[32];
    unsigned char gf_const_tbl_b[32];
    gf_vect_mul_init(a, gf_const_tbl_a);
    gf_vect_mul_init(b, gf_const_tbl_b);

    gf_vect_mul(TEST_LEN, gf_const_tbl_a, buffs2[TEST_SOURCES], tmp_buf[3]);
    gf_vect_mul(TEST_LEN, gf_const_tbl_b, buffs2[TEST_SOURCES + 1], buffs2[3]);
    xor_buf(buffs2[3], tmp_buf[3], TEST_LEN);

    memcpy(buffs2[8], buffs2[3], TEST_LEN);
    xor_buf(buffs2[8], buffs2[TEST_SOURCES], TEST_LEN);

    for (i = 0; i < TEST_LEN; i++) {
        if (((char *)buffs[3])[i] != ((char *)buffs2[3])[i]) {
            fail++;
        }
        if (((char *)buffs[8])[i] != ((char *)buffs2[8])[i]) {
            fail++;
        }
    }

    if (fail > 0) {
        printf("fail d+d test %d\n", fail);
        return 1;
    } else
        putchar('.');

    fflush(0);


    if (!fail)
        printf(" done: Pass\n");

    return fail;
}