#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "openssl\aes_defs.h"
#include "openssl\aes_ccmp.h"


static const uint8_t key[] = { 0x06, 0x17, 0x3B, 0xB8, 0xDE, 0x44, 0xB5, 0xEA, 0xF8, 0x48, 0xF6, 0xAF, 0x6F, 0xD1, 0x0A, 0xA4 };
static AES_KEY priv_key_enc, priv_key_dec;

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

    cbc_mac_enc(a, m, la, lm, saddr, asn, key, mac, 4, AES_CBC_MAC_HW);
    printf("MAC %02X %02X %02X %02X\n", mac[0], mac[1], mac[2], mac[3]);
    mac[0] = mac[1] = mac[2] = mac[3] = 0;
    cbc_mac_enc(a, m, la, lm, saddr, asn, key, mac, 4, AES_CBC_MAC_FW);
    printf("MAC %02X %02X %02X %02X\n", mac[0], mac[1], mac[2], mac[3]);

    return 0;
}

