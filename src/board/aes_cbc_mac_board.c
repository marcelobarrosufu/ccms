#include <stdint.h>
#include <string.h>
#include "openssl\aes_defs.h"
#include "aes_ecb.h"
#include "aes_cbc_mac_board.h"

int aes_cbc_mac_board_enc_raw(uint8_t *buffer, uint8_t len, uint8_t key[16])
{
    AES_KEY key_enc;
    uint8_t iv[16];

    memset(iv, 0, 16);
    AES_set_encrypt_key(key, 128, &key_enc);
    AES_cbc_encrypt(buffer, buffer, len, &key_enc, iv, AES_ENCRYPT);

    return 0;
}

int aes_cbc_mac_board_enc(uint8_t *a,
                uint8_t len_a,
                uint8_t *m,
                uint8_t len_m,
                uint8_t saddr[8],
                uint8_t asn[5],
                uint8_t *key,
                uint8_t *mac,
                uint8_t len_mac)
{
    return -1;
}

