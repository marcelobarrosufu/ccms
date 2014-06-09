#ifndef __AES_ECB_H__
#define __AES_ECB_H__

#ifdef  __cplusplus
extern "C" {
#endif

int aes_ecb_enc_hw(uint8_t *buffer, uint8_t *key);
int aes_ecb_enc_fw(uint8_t *buffer, uint8_t *key);
int aes_ecb_enc(uint8_t *buffer, uint8_t *key);

#ifdef  __cplusplus
}
#endif

#endif /* __AES_ECB_H__ */
