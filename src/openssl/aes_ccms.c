#include <string.h>
#include <stdint.h>
#include "openssl\aes_defs.h"
#include "openssl\aes_ccms.h"

int cbc_mac_enc_fw(uint8_t *buffer, uint8_t len, AES_KEY *key_enc)
{
    uint8_t n, k, nb, *pbuf;

    nb = len >> 4;
    for (n = 0; n < nb; n++) {
        pbuf = &buffer[16 * n];
        AES_ecb_encrypt(pbuf, pbuf, key_enc, AES_ENCRYPT);
        if (n < (nb - 1)) {
            // may be faster if vector are aligned to 4 bytes (use long instead char in xor)
            for (k = 0; k < 16; k++){
                pbuf[16 + k] ^= pbuf[k];
            }
        }
    }

    return 0;
}

int cbc_mac_enc(uint8_t *a, 
                uint8_t *m,
                uint8_t len_a,
                uint8_t len_m,
                uint8_t saddr[8],
                uint8_t asn[5],
                uint8_t *key,
                uint8_t *mac,
                uint8_t len_mac,
                uint8_t cbc_mac_support)
{
    uint8_t pad_len;
    uint8_t len;
    uint8_t iv[16];
    uint8_t buffer[128+16]; // max buffer plus IV
    AES_KEY key_enc;

    // asserts here
    if (!((len_mac == 4) || (len_mac == 8) || (len_mac == 16)))
        return -1;

    if ((len_a > 127) || (len_m > 127) || ((len_a + len_m) > 127))
        return -2;

    if (mac == 0)
        return -3;

    if (!((cbc_mac_support == AES_CBC_MAC_HW) || (cbc_mac_support == AES_CBC_MAC_FW)))
        return -4;

    // IV: flags (1B) | SADDR (8B) | ASN (5B) | len(m) (2B)
    // X0 xor IV in first 16 bytes of buffer
    // (openssl will start with buffer[:16]^IV so use IV as zero and set buffer[:16] as IV)
    memset(iv, 0, 16); 
    buffer[0] = 0;
    buffer[1] = len_m;
    memcpy(&buffer[2], asn, 5); // assign byte by byte or copy ?
    memcpy(&buffer[7], saddr, 8);
    buffer[15] = 0x49;
    len = 16;

    // len(a)
    buffer[16] = 0;
    buffer[17] = len_a;
    len += 2;

    //  (((x >> 4) + 1)<<4) - x   or    16 - (x % 16) ?
    // a + padding
    pad_len = ((((len_a + 2) >> 4) + 1) << 4) - (len_a + 2);
    pad_len = pad_len == 16 ? 0 : pad_len;
    memcpy(&buffer[len], a, len_a);
    len += len_a;
    memset(&buffer[len], 0, pad_len);
    len += pad_len;

    // m + padding
    pad_len = (((len_m >> 4) + 1) << 4) - len_m;
    pad_len = pad_len == 16 ? 0 : pad_len;
    memcpy(&buffer[len], m, len_m);
    len += len_m;
    memset(&buffer[len], 0, pad_len);
    len += pad_len;

    AES_set_encrypt_key(key, 128, &key_enc);

    if (cbc_mac_support == AES_CBC_MAC_HW)
        AES_cbc_encrypt(buffer, buffer, len, &key_enc, iv, AES_ENCRYPT);
    else
        cbc_mac_enc_fw(buffer,len,&key_enc);

    memcpy(mac, &buffer[len - 16], len_mac);

    return 0;
}
