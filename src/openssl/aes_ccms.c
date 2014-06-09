#include <string.h>
#include <stdint.h>
// openssl
#include <openssl\aes.h>
#include <openssl\modes.h>
#include "openssl\aes_defs.h"
#include "openssl\aes_ctr.h"
#include "openssl\aes_cbc_mac.h"
#include "openssl\aes_ccms.h"

int aes_ccms_enc(uint8_t *a,
             uint8_t len_a,
             uint8_t *m,
             uint8_t len_m,
             uint8_t saddr[8],
             uint8_t asn[5],
             uint8_t *key,
             uint8_t *mac,
             uint8_t mac_len)
{
    if (aes_cbc_mac_enc(a, len_a, m, len_m, saddr, asn, key, mac, mac_len) == 0) 
        if (aes_ctr_enc(m, len_m, saddr, asn, key, mac, mac_len) == 0)
            return 0;
    
    return -1;
}