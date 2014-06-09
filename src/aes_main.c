#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "openssl\aes_defs.h"
#include "openssl\aes_cbc_mac.h"
#include "openssl\aes_ctr.h"

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

int main(int argc, char* argv[])
{
    
    uint8_t key[] = { 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF };
    uint8_t saddr[] = { 0xAC, 0xDE, 0x48, 0x00, 0x00, 0x00, 0x00, 0x01 };
    uint8_t asn[] = { 0x00, 0x00, 0x00, 0x00, 0x05};
    uint8_t m[] = { 0x61, 0x62, 0x63, 0x64 };
    uint8_t m2[] = { 0x61, 0x62, 0x63, 0x64 };
    uint8_t lm = 4;
    uint8_t a[] = { 0x69, 0xDC, 0x84, 0x21, 0x43, 0x02, 0x00, 0x00, 0x00, 0x00, 0x48, 0xDE, 0xAC, 0x01, 0x00, 0x00, 0x00, 0x00, 0x48, 0xDE, 0xAC, 0x05};
    uint8_t la = 22;
    uint8_t mac[4];
    uint8_t mac2[4];

    aes_cbc_mac_enc(a, la, m, lm, saddr, asn, key, mac, 4, AES_CBC_MAC_HW);
    printf("\nMAC HW:");
    dump_frame(mac, 5);

    mac[0] = mac[1] = mac[2] = mac[3] = 0;
    aes_cbc_mac_enc(a, la, m, lm, saddr, asn, key, mac, 4, AES_CBC_MAC_FW);
    printf("\nMAC FW:");
    dump_frame(mac, 5);
    memcpy(mac2, mac, 4);

    aes_ctr_enc(m, lm, saddr, asn, key, mac, 4, AES_CTR_HW);

    printf("\nE. PAYLOAD HW: ");
    dump_frame(m, lm);
    printf("\nE. MAC HW    : "); 
    dump_frame(mac, 4);

    aes_ctr_enc(m2, lm, saddr, asn, key, mac2, 4, AES_CTR_FW);

    printf("\nE. PAYLOAD FW: ");
    dump_frame(m2, lm);
    printf("\nE. MAC FW    : ");
    dump_frame(mac2, 4);

    return 0;
}

