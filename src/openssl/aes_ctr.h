#ifndef __AES_CTR_H__
#define __AES_CTR_H__

#ifdef  __cplusplus
extern "C" {
#endif

enum AES_CTR_E {
    AES_CTR_HW,
    AES_CTR_FW
};

int aes_ctr_enc(uint8_t *m,
    uint8_t len_m,
    uint8_t saddr[8],
    uint8_t asn[5],
    uint8_t *key,
    uint8_t *mac,
    uint8_t len_mac,
    uint8_t aes_ctr_support);

#ifdef  __cplusplus
}
#endif

#endif /* __AES_CTR_H__ */
