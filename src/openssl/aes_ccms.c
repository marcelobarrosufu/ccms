#include <string.h>
#include <stdint.h>
// openssl
#include <openssl\aes.h>
#include <openssl\modes.h>
#include "openssl\aes_defs.h"
#include "openssl\aes_ccms.h"

int aes_ccms(uint8_t *a,
             uint8_t len_a,
             uint8_t *m,
             uint8_t len_m,
             open_addr_t *saddr,
             asn_t *asn,
             uint8_t *key)
{
    int addr_size;
    int n;
    uint8_t _saddr[8];
    uint8_t _asn[5];
    uint8_t mac[4];

    // copy source addr
    switch (saddr->type) {
        case ADDR_16B:
        case ADDR_PANID:
            addr_size = 2;
            break;
        case ADDR_64B:
        case ADDR_PREFIX:
            addr_size = 8;
            break;
        case ADDR_128B:
            addr_size = 16;
            break;
        default:
            addr_size = -1;
            break;
    }

    if (addr_size == -1)
        return -1;

    if (addr_size > 8)
        addr_size = 8;
    
    for (n = 0; n < addr_size; n++) 
        _saddr[n] = saddr->addr_128b[n];
    
    if (addr_size < 8)
        memset(&_saddr[addr_size], 0, 8 - addr_size);

    // copy ASN
    _asn[0] = (uint8_t) (asn->bytes0and1 >> 8); 
    _asn[1] = (uint8_t) asn->bytes0and1;
    _asn[2] = (uint8_t) (asn->bytes2and3 >> 8);
    _asn[3] = (uint8_t) asn->bytes2and3;
    _asn[4] = (uint8_t) asn->byte4;

}