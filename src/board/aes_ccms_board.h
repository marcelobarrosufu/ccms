/**
\brief Definitions for CCMS entry points

\author Marcelo Barros de Almeida <marcelobarrosalmeida@gmail.com>
*/
#ifndef __AES_CCMS_BOARD_H__
#define __AES_CCMS_BOARD_H__

#ifdef  __cplusplus
extern "C" {
#endif

int aes_ccms_board_enc(uint8_t *a, uint8_t len_a, uint8_t *m, uint8_t *len_m, uint8_t saddr[8], uint8_t asn[5], uint8_t *key);
int aes_ccms_board_dec(uint8_t *a, uint8_t len_a, uint8_t *m, uint8_t *len_m, uint8_t saddr[8], uint8_t asn[5], uint8_t *key);

#ifdef  __cplusplus
}
#endif

#endif /* __AES_CCMS_BOARD_H__ */
