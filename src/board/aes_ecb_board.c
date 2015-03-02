/**
\brief AES ECB entry point

\author Marcelo Barros de Almeida <marcelobarrosalmeida@gmail.com>
*/
#include <stdint.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include <openssl/aes_defs.h>
#include "aes_ecb_board.h"

int aes_ecb_board_enc(uint8_t *buffer, uint8_t *key)
{
    AES_KEY key_enc;
    AES_set_encrypt_key(key, 128, &key_enc);
    AES_encrypt(buffer, buffer, &key_enc);

    return 0;
}

