#include <stdint.h>
#include <string.h>
#include "openssl\aes_defs.h"
#include "aes_ctr_board.h"

// openssl
static void AES_ctr128_encrypt(const unsigned char *in, unsigned char *out,
    size_t length, const AES_KEY *key,
    unsigned char ivec[AES_BLOCK_SIZE],
    unsigned char ecount_buf[AES_BLOCK_SIZE],
    unsigned int *num) {
    CRYPTO_ctr128_encrypt(in, out, length, key, ivec, ecount_buf, num, (block128_f) AES_encrypt);
}

int aes_ctr_board_enc_raw(uint8_t *buffer, uint8_t len, uint8_t *key, uint8_t iv[16])
{
    uint8_t ebuf[16];
    uint32_t num;
    AES_KEY key_enc;

    num = 0;
    memset(ebuf, 0, 16);
    AES_set_encrypt_key(key, 128, &key_enc);
    AES_ctr128_encrypt(buffer, buffer, len, &key_enc, iv, ebuf, &num);

    return 0;
}

int aes_ctr_board_enc(uint8_t *m,
    uint8_t len_m,
    uint8_t saddr[8],
    uint8_t asn[5],
    uint8_t *key,
    uint8_t *mac,
    uint8_t len_mac)
{
    return -1;
}
