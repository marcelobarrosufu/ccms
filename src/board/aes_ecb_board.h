/**
\brief Definitions for AES ECB entry point

\author Marcelo Barros de Almeida <marcelobarrosalmeida@gmail.com>
*/
#ifndef __AES_ECB_BOARD_H__
#define __AES_ECB_BOARD_H__

#ifdef  __cplusplus
extern "C" {
#endif

int aes_ecb_board_enc(uint8_t *buffer, uint8_t *key);

#ifdef  __cplusplus
}
#endif

#endif /* __AES_ECB_BOARD_H__ */
