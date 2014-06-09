#include <string.h>
#include <stdint.h>
// openssl
#include <openssl\aes.h>
#include <openssl\modes.h>
#include "openssl\aes_defs.h"
#include "openssl\aes_ctr.h"

// openssl
static void AES_ctr128_encrypt(const unsigned char *in, unsigned char *out,
    size_t length, const AES_KEY *key,
    unsigned char ivec[AES_BLOCK_SIZE],
    unsigned char ecount_buf[AES_BLOCK_SIZE],
    unsigned int *num) {
    CRYPTO_ctr128_encrypt(in, out, length, key, ivec, ecount_buf, num, (block128_f) AES_encrypt);
}

// openssl
static void inc_counter(unsigned char *counter) 
{
    u32 n = 16;
    u8  c;
    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c) return;
    } while (n);
}

int aes_ctr_enc_hw(uint8_t *buffer, uint8_t len, uint8_t *key, uint8_t iv[16])
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

int aes_ctr_enc_fw(uint8_t *buffer, uint8_t len, uint8_t *key, uint8_t iv[16])
{
    uint8_t n, k, nb, *pbuf;
    uint8_t eiv[16];
    AES_KEY key_enc;

    AES_set_encrypt_key(key, 128, &key_enc);

    nb = len >> 4;
    for (n = 0; n < nb; n++) {
        pbuf = &buffer[16 * n];
        AES_ecb_encrypt(iv, eiv, &key_enc, AES_ENCRYPT);
        // may be faster if vector are aligned to 4 bytes (use long instead char in xor)
        for (k = 0; k < 16; k++){
           pbuf[k] ^= eiv[k];
        }
        inc_counter(iv);
    }

    return 0;

}

int aes_ctr_enc(uint8_t *m,
    uint8_t len_m,
    uint8_t saddr[8],
    uint8_t asn[5],
    uint8_t *key,
    uint8_t *mac,
    uint8_t len_mac)
{
    uint8_t pad_len;
    uint8_t len;
    uint8_t iv[16];
    uint8_t buffer[128 + 16]; // max buffer plus mac

    // asserts here
    if (!((len_mac == 4) || (len_mac == 8) || (len_mac == 16)))
        return -1;

    if (len_m > 127)
        return -2;

    if (mac == 0)
        return -3;

    // iv (flag (1B) | source addr (8B) | ASN (5B) | cnt (2B)
    iv[0] = 0x01;
    memcpy(&iv[1], saddr, 8);
    memcpy(&iv[9], asn, 5); // assign byte by byte or copy ?
    iv[14] = 0x00;
    iv[15] = 0x00;

    // first block is mac
    memcpy(buffer, mac, len_mac);
    memset(&buffer[len_mac], 0, 16 - len_mac);
    len = 16;

    //  (((x >> 4) + 1)<<4) - x   or    16 - (x % 16) ?
    // m + padding
    pad_len = (((len_m >> 4) + 1) << 4) - len_m;
    pad_len = pad_len == 16 ? 0 : pad_len;
    memcpy(&buffer[len], m, len_m);
    len += len_m;
    memset(&buffer[len], 0, pad_len);
    len += pad_len;

    if (AES_CTR_SUPPORT == AES_CTR_HW)
        aes_ctr_enc_fw(buffer, len, key, iv);
    else
        aes_ctr_enc_fw(buffer, len, key, iv);

    memcpy(m, &buffer[16], len_m);
    memcpy(mac, buffer, len_mac);

    return 0;
}
