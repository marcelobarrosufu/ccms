#ifndef __AES_CONFIG_H__
#define __AES_CONFIG_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// Use assembly
#undef AES_ASM
// #define AES_ASM 1

// Unroll for loops for 
#undef FULL_UNROLL
//define FULL_UNROLL 1

// Only accept aligned points 
#undef STRICT_ALIGNMENT
//#define STRICT_ALIGNMENT 1

// Try to generate a smaller openssl lib
#undef OPENSSL_SMALL_FOOTPRINT
//#define OPENSSL_SMALL_FOOTPRINT 1

//  Block low level AES calls in FIPS mode
#undef OPENSSL_FIPS
//#define OPENSSL_FIPS 1

#define OPENSSL_VERSION_NUMBER	0x1000107fL
#define OPENSSL_VERSION_TEXT	"OpenSSL 1.0.1g 7 Apr 2014"
#define OPENSSL_VERSION_PTEXT	" part of " OPENSSL_VERSION_TEXT

#define AES_MAXNR 14
#define AES_BLOCK_SIZE 16
#define AES_ENCRYPT	1
#define AES_DECRYPT	0

#define GETU32(p)	((u32)(p)[0]<<24|(u32)(p)[1]<<16|(u32)(p)[2]<<8|(u32)(p)[3])
#define PUTU32(p,v)	((p)[0]=(u8)((v)>>24),(p)[1]=(u8)((v)>>16),(p)[2]=(u8)((v)>>8),(p)[3]=(u8)(v))

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;

struct aes_key_st {
	unsigned long rd_key[4 * (AES_MAXNR + 1)];
	int rounds;
};

typedef struct aes_key_st AES_KEY;

void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);

typedef void (*block128_f)(const unsigned char in[16], unsigned char out[16], const void *key);
typedef void(*cbc128_f)(const unsigned char *in, unsigned char *out, size_t len, const void *key, unsigned char ivec[16], int enc);
typedef void(*ctr128_f)(const unsigned char *in, unsigned char *out, size_t blocks, const void *key, const unsigned char ivec[16]);

void CRYPTO_cbc128_encrypt(const unsigned char *in, unsigned char *out,	size_t len, const void *key, unsigned char ivec[16], block128_f block);
void CRYPTO_cbc128_decrypt(const unsigned char *in, unsigned char *out,	size_t len, const void *key, unsigned char ivec[16], block128_f block);
void CRYPTO_ctr128_encrypt(const unsigned char *in, unsigned char *out, size_t len, const void *key, unsigned char ivec[16], 
	                       unsigned char ecount_buf[16], unsigned int *num, block128_f block);

void AES_ecb_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key, const int enc);
void AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t length, const AES_KEY *key, unsigned char *ivec, const int enc);
void AES_ctr128_encrypt(const unsigned char *in, unsigned char *out, size_t length, const AES_KEY *key, unsigned char ivec[AES_BLOCK_SIZE], 
	                    unsigned char ecount_buf[AES_BLOCK_SIZE], unsigned int *num);

int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);

int private_AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
int private_AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);

#ifdef  __cplusplus
}
#endif

#endif /* __AES_CONFIG_H__ */
