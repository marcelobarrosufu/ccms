#include <string.h>
#include <stdint.h>
#include "crypto_driver.h"

int aes_ccms_board_enc(uint8_t *a,
                       uint8_t len_a,
                       uint8_t *m,
                       uint8_t *len_m,
                       uint8_t saddr[8],
                       uint8_t asn[5],
                       uint8_t *key)
{
    return -1;
}

int aes_ccms_board_dec(uint8_t *a,
                       uint8_t len_a,
                       uint8_t *m,
                       uint8_t *len_m,
                       uint8_t saddr[8],
                       uint8_t asn[5],
                       uint8_t *key)
{
    return -1;
}