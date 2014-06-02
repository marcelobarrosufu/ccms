#ifndef __AES_CCMP_H__
#define __AES_CCMP_H__

#ifdef  __cplusplus
extern "C" {
#endif

enum AES_CCMP_e {
    AES_CBC_MAC_HW,
    AES_CBC_MAC_FW,
};

int cbc_mac_enc_fw(uint8_t *buffer, uint8_t len, AES_KEY *key_enc);
int cbc_mac_enc(uint8_t *a, 
                uint8_t *m,
                uint8_t len_a,
                uint8_t len_m,
                uint8_t saddr[8],
                uint8_t asn[5],
                uint8_t *key,
                uint8_t *mac,
                uint8_t len_mac,
                uint8_t cbc_mac_support);
                
#ifdef  __cplusplus
}
#endif

#endif /* __AES_CCMP_H__ */
