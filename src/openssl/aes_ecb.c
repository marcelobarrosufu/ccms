#include <string.h>
#include <stdint.h>
// openssl
#include <openssl\aes.h>
#include <openssl\modes.h>
#include "openssl\aes_defs.h"
#include "openssl\aes_ecb.h"

int aes_ecb_enc_hw(uint8_t *buffer, uint8_t *key)
{
    // not implemented
    return 0;
}
int aes_ecb_enc_fw(uint8_t *buffer, uint8_t *key)
{
    AES_KEY key_enc;
    AES_set_encrypt_key(key, 128, &key_enc);
    AES_encrypt(buffer, buffer, &key_enc);

    return 0;
}

int aes_ecb_enc(uint8_t *buffer, uint8_t *key)
{
    if (AES_ECB_SUPPORT == AES_ECB_FW)
        aes_ecb_enc_fw(buffer, key);
    else
        aes_ecb_enc_hw(buffer, key);

    return 0;
}
