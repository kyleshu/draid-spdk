#include "isa-l/include/raid.h"
#include "isa-l/include/gf_vect_mul.h"
#include "spdk/stdinc.h"
#include "spdk/string.h"

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

    for (i = 0; i < base_devs - 2; i++) {
        gf_vect_mul_init(i, gf_const_tbl_arr[i]);
    }

    for (i = 0; i < base_devs - 2; i++) {
        for (j = 0; j < data_size; j++) {
            data[i][j] = (char) rand();
        }
        memcpy(data2[i], data[i], data_size);
    }

    for (i = base_devs - 2; i < base_devs; i++) {
        memset(data[i], 0, data_size);
        memset(data2[i], 0, data_size);
    }

    ret = pq_gen(base_devs, data_size, (void **) data);
    assert(ret == 0);

    return 0;
}