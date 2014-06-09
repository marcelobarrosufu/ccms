#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "openssl\aes_defs.h"
#include "openssl\aes_cbc_mac.h"
#include "openssl\aes_ctr.h"
#include "openssl\aes_ccms.h"

static const uint8_t key[] = { 0x06, 0x17, 0x3B, 0xB8, 0xDE, 0x44, 0xB5, 0xEA, 0xF8, 0x48, 0xF6, 0xAF, 0x6F, 0xD1, 0x0A, 0xA4 };
static AES_KEY priv_key_enc, priv_key_dec;

static void dump_frame(unsigned char *data, int len)
{
    int i, j, k;
    unsigned char buf[50];
    for (k = 0; k < len; k += 16)
    {
        for (i = k, j = 0; (i< (k + 16)) && (i < len); i++, j += 3)
            sprintf((char *) &buf[j], "%02X ", data[i]);
        buf[j] = '\0';
        printf("%s", buf);
    }
}

static int translate_addr(open_addr_t *saddr, uint8_t _saddr[8])
{
    int n;
    int addr_size;

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

    return 0;
}

static int translate_asn(asn_t *asn, uint8_t _asn[5])
{
    _asn[0] = (uint8_t) (asn->bytes0and1 >> 8);
    _asn[1] = (uint8_t) asn->bytes0and1;
    _asn[2] = (uint8_t) (asn->bytes2and3 >> 8);
    _asn[3] = (uint8_t) asn->bytes2and3;
    _asn[4] = (uint8_t) asn->byte4;

    return 0;
}

int main(int argc, char* argv[])
{
    
    uint8_t key[] = { 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF };
    uint8_t saddr[] = { 0xAC, 0xDE, 0x48, 0x00, 0x00, 0x00, 0x00, 0x01 };
    uint8_t asn[] = { 0x00, 0x00, 0x00, 0x00, 0x05};
    uint8_t m[] = { 0x61, 0x62, 0x63, 0x64 };
    uint8_t lm = 4;
    uint8_t a[] = { 0x69, 0xDC, 0x84, 0x21, 0x43, 0x02, 0x00, 0x00, 0x00, 0x00, 0x48, 0xDE, 0xAC, 0x01, 0x00, 0x00, 0x00, 0x00, 0x48, 0xDE, 0xAC, 0x05};
    uint8_t la = 22;
    uint8_t mac[4];

    printf("\n --------------------------");
    printf("\nHEADER  : "); dump_frame(a, la);
    printf("\nPAYLOAD : "); dump_frame(m, lm);
    printf("\n --------------------------");

    aes_ccms_enc(a, la, m, lm, saddr, asn, key, mac, 4);
    
    printf("\nEPAYLOAD: "); dump_frame(m, lm);
    printf("\nEMAC    : "); dump_frame(mac, 4);
    printf("\n --------------------------");

    aes_ccms_enc(a, la, m, lm, saddr, asn, key, mac, 4);
    printf("\nHEADER  : "); dump_frame(a, la);
    printf("\nPAYLOAD : "); dump_frame(m, lm);

    return 0;
}

