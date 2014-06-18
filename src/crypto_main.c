#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "crypto_driver.h"

static const uint8_t key[] = { 0x06, 0x17, 0x3B, 0xB8, 0xDE, 0x44, 0xB5, 0xEA, 0xF8, 0x48, 0xF6, 0xAF, 0x6F, 0xD1, 0x0A, 0xA4 };

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

int main(int argc, char* argv[])
{
    
    uint8_t key[] = { 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF };
    uint8_t saddr[] = { 0xAC, 0xDE, 0x48, 0x00, 0x00, 0x00, 0x00, 0x01 };
    uint8_t asn[] = { 0x00, 0x00, 0x00, 0x00, 0x05};
    uint8_t m[] = { 0x61, 0x62, 0x63, 0x64, 0x12, 0xff, /* reserve space for mac */ 0x00, 0x00, 0x00, 0x00 };
    uint8_t lm = 6;
    uint8_t a[] = { 0x69, 0xDC, 0x84, 0x21, 0x43, 0x02, 0x00, 0x00, 0x00, 0x00, 0x48, 0xDE, 0xAC, 0x01, 0x00, 0x00, 0x00, 0x00, 0x48, 0xDE, 0xAC, 0x05};
    uint8_t la = 22;
    const crypto_driver_t* drv;

    crypto_driver_init();

    drv = crypto_driver_get();

    printf("\n --------------------------");
    printf("\nHEADER  : "); dump_frame(a, la);
    printf("\nPAYLOAD : "); dump_frame(m, lm);
    printf("\n --------------------------");

    if (drv->aes_ccms_enc(a, la, m, &lm, saddr, asn, key) == 0)
    {
        printf("\nEPAYLOAD: "); dump_frame(m, lm);
        printf("\n --------------------------");

        if (drv->aes_ccms_dec(a, la, m, &lm, saddr, asn, key) == 0)
        {
            printf("\nHEADER  : "); dump_frame(a, la);
            printf("\nPAYLOAD : "); dump_frame(m, lm);
        }
        else
        {
            printf("\nDecoding error ... \n");
        }
    }
    else
    {
        printf("\nEncoding error ... \n");
    }

    return 0;
}

