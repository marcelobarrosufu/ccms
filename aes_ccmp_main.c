/*

D:\apps\conemu>\apps\OpenSSL-Win64\bin\openssl.exe enc -aes-128-cbc -k OpenWSN -P -md sha1

salt=3B063EFBAB66F3B2
key=06173BB8DE44B5EAF848F6AF6FD10AA4
iv =EE168E336C0D7703E95E2529DD7118D5


*/
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "openssl\aes_defs.h"

enum {
    AES_CBC_MAC_HW,
    AES_CBC_MAC_FW,
};
static const uint8_t key[] = { 0x06, 0x17, 0x3B, 0xB8, 0xDE, 0x44, 0xB5, 0xEA, 0xF8, 0x48, 0xF6, 0xAF, 0x6F, 0xD1, 0x0A, 0xA4 };
static AES_KEY priv_key_enc, priv_key_dec;

int cbc_mac_enc_fw(uint8_t *buffer, uint8_t len, AES_KEY *key_enc)
{
    uint8_t n, k, nb, *pbuf;

    nb = len >> 4;
    for (n = 0; n < nb; n++) {
        pbuf = &buffer[16 * n];
        AES_ecb_encrypt(pbuf, pbuf, key_enc, AES_ENCRYPT);
        if (n < (nb - 1)) {
            // may be faster if vector are aligned to 4 bytes (use long instead char in xor)
            for (k = 0; k < 16; k++){
                pbuf[16 + k] ^= pbuf[k];
            }
        }
    }

    return 0;
}

int cbc_mac_enc(uint8_t *a, 
			    uint8_t *m,
			    uint8_t len_a,
				uint8_t len_m,
				uint8_t saddr[8],
				uint8_t asn[5],
				uint8_t *key,
				uint8_t *mac,
				uint8_t len_mac,
                uint8_t cbc_mac_support)
{
	uint8_t pad_len;
	uint8_t len;
	uint8_t iv[16];
	uint8_t buffer[128+16]; // max buffer plus IV
	AES_KEY key_enc;

	// asserts here
	if (!((len_mac == 4) || (len_mac == 8) || (len_mac == 16)))
		return -1;

	if ((len_a > 127) || (len_m > 127) || ((len_a + len_m) > 127))
		return -2;

	if (mac == 0)
		return -3;

    if (!((cbc_mac_support == AES_CBC_MAC_HW) || (cbc_mac_support == AES_CBC_MAC_FW)))
        return -4;

	// IV: flags (1B) | SADDR (8B) | ASN (5B) | len(m) (2B)
    // X0 xor IV in first 16 bytes of buffer
    // (openssl will start with buffer[:16]^IV so use IV as zero and set buffer[:16] as IV)
    memset(iv, 0, 16); 
    buffer[0] = 0;
    buffer[1] = len_m;
    memcpy(&buffer[2], asn, 5); // assign byte by byte or copy ?
    memcpy(&buffer[7], saddr, 8);
    buffer[15] = 0x49;
    len = 16;

    // len(a)
    buffer[16] = 0;
    buffer[17] = len_a;
	len += 2;

    //  (((x >> 4) + 1)<<4) - x   or    16 - (x % 16) ?
    // a + padding
	pad_len = ((((len_a + 2) >> 4) + 1) << 4) - (len_a + 2);
	pad_len = pad_len == 16 ? 0 : pad_len;
    memcpy(&buffer[len], a, len_a);
	len += len_a;
    memset(&buffer[len], 0, pad_len);
	len += pad_len;

	// m + padding
	pad_len = (((len_m >> 4) + 1) << 4) - len_m;
	pad_len = pad_len == 16 ? 0 : pad_len;
    memcpy(&buffer[len], m, len_m);
	len += len_m;
    memset(&buffer[len], 0, pad_len);
	len += pad_len;

	AES_set_encrypt_key(key, 128, &key_enc);

    if (cbc_mac_support == AES_CBC_MAC_HW)
        AES_cbc_encrypt(buffer, buffer, len, &key_enc, iv, AES_ENCRYPT);
    else
        cbc_mac_enc_fw(buffer,len,&key_enc);

	memcpy(mac, &buffer[len - 16], len_mac);

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

    cbc_mac_enc(a, m, la, lm, saddr, asn, key, mac, 4, AES_CBC_MAC_HW);
    printf("MAC %02X %02X %02X %02X\n", mac[0], mac[1], mac[2], mac[3]);
    mac[0] = mac[1] = mac[2] = mac[3] = 0;
    cbc_mac_enc(a, m, la, lm, saddr, asn, key, mac, 4, AES_CBC_MAC_FW);
    printf("MAC %02X %02X %02X %02X\n", mac[0], mac[1], mac[2], mac[3]);

	return 0;

#if 0
	int r, n, m;
	unsigned char iv[16];
	unsigned char orig_text[128], clear_text[128], cipher_text[128];

	AES_set_encrypt_key(key, 128, &priv_key_enc);
	AES_set_decrypt_key(key, 128, &priv_key_dec);
	
	for (n = 0; n < 16; n++)
		iv[n] = n;

	for (m = 0; m < 4; m++) {
		for (n = 0; n < 10; n++) {
			clear_text[n + m * 10] = orig_text[n + m * 10] = n + '0';
		}
	}

	AES_cbc_encrypt(clear_text, cipher_text, 32, &priv_key_enc, iv, AES_ENCRYPT);

	for (n = 0; n < 16; n++)
		iv[n] = n;

	AES_cbc_encrypt(cipher_text, clear_text, 32, &priv_key_dec, iv, AES_DECRYPT);

	/*
	for (m = 0; m < 2; m++) {
		for (n = 0; n < 10; n++) {
			clear_text[n + m * 10] = orig_text[n + m * 10] = n + '0';
		}
	}

	AES_ecb_encrypt(clear_text, cipher_text, &priv_key_enc, AES_ENCRYPT);

	for (m = 0; m < 2; m++) {
		for (n = 0; n < 10; n++) {
			clear_text[n + m * 10] = 0;
		}
	}

	for (n = 0; n < 16; n++)
		iv[n] = n;
	
	AES_ecb_encrypt(cipher_text, clear_text, &priv_key_dec, AES_DECRYPT);
	*/
	return 0;
#endif
}

