#ifndef __AES_CCMS_H__
#define __AES_CCMS_H__

#ifdef  __cplusplus
extern "C" {
#endif

int aes_ccms_enc(uint8_t *a,
             uint8_t len_a,
             uint8_t *m,
             uint8_t len_m,
             uint8_t saddr[8],
             uint8_t asn[5],
             uint8_t *key, 
             uint8_t *mac,
             uint8_t mac_len);

#ifdef  __cplusplus
}
#endif

#endif /* __AES_CCMS_H__ */
