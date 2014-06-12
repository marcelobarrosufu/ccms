#ifndef __AES_CTR_H__
#define __AES_CTR_H__

#ifdef  __cplusplus
extern "C" {
#endif

int aes_ctr_enc_hw(uint8_t *buffer, uint8_t len, uint8_t *key, uint8_t iv[16]);
int aes_ctr_enc_fw(uint8_t *buffer, uint8_t len, uint8_t *key, uint8_t iv[16]);

int aes_ctr_enc(uint8_t *m,
    uint8_t len_m,
    uint8_t saddr[8],
    uint8_t asn[5],
    uint8_t *key,
    uint8_t *mac,
    uint8_t len_mac);

#ifdef  __cplusplus
}
#endif

#endif /* __AES_CTR_H__ */