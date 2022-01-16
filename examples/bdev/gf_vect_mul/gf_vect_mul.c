#include "isa-l/include/raid.h"
#include "isa-l/include/gf_vect_mul.h"
#include "spdk/stdinc.h"
#include "spdk/string.h"
#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char **argv)
{
    uint8_t base_devs = 16;
    size_t data_size = 4096;
    uint8_t i, j;
    uint8_t gf_const_tbl_arr[base_devs][32];
    char data[base_devs][data_size];
    char data2[base_devs][data_size];
    int ret;
    char tmp;

    printf("start\n");

    for (i = 0; i < base_devs - 2; i++) {
        gf_vect_mul_init(i, gf_const_tbl_arr[i]);
    }

    printf("gf_vect_mul_init\n");

    for (i = 0; i < base_devs - 2; i++) {
        tmp = rand();
        memset(data[i], tmp, data_size);
        memset(data2[i], tmp, data_size);
    }

    for (i = base_devs - 2; i < base_devs; i++) {
        memset(data[i], 0, data_size);
        memset(data2[i], 0, data_size);
    }

    printf("memset\n");

    ret = pq_gen(base_devs, data_size, (void **) data);
    assert(ret == 0);

    return 0;
}