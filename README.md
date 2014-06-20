ccms
====

CCM* implementation for 802.15.4e 2012 networks

As we may have many combinations of hardware and software, this implementation 
was based on a driver concept where board specific code is responsible to 
initialize function pointers for all crypto functionalities.

There are seven function to be created:

| Function | Description |
|----------|-------------|
| aes_ecb_enc | basic AES-128 encoder. |
| aes_cbc_mac_enc | Entry point for CBC-MAC encoder where several buffer operations are required to create the initialization vector and required paddings. aes_cbc_mac_enc_raw is called after buffer processing. |
| aes_cbc_mac_enc_raw | Basic CBC-MAC encoder. |
| aes_ctr_enc | Entry point for CTR encoder where several buffer operations are required to create the initialization vector and required paddings |
| aes_ctr_enc_raw | Basic CTR encoder. |
| aes_ccms_enc | CCM* encoder. |
| aes_ccms_dec | CCM* decoder. |

All later usage is simple and based on driver calls. For instance:

```c
 uint8_t key[] = { 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF };
 uint8_t buffer[] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
 const crypto_driver_t* drv;

 crypto_driver_init(); // platform dependent call
 drv = crypto_driver_get();
 drv->aes_ecb_enc(buffer, key); // buffer is encrypted using key
```

When initializing the driver, the developer needs to decide which set of functions to use (see the file crypto_driver_board.c). The proposed functions can be used or some specific functions, crafted for its crypto engine. In this case, it is necessary to create them (*_board.c|h files) and initialize the driver properly.

```c
int crypto_driver_board_init(crypto_driver_t *crypto_driver)
{
    /* CCM*. CBC-MAC provided by firmware */
    crypto_driver->aes_ccms_dec = aes_ccms_dec;
    crypto_driver->aes_ccms_enc = aes_ccms_enc;
    crypto_driver->aes_cbc_mac_enc = aes_cbc_mac_enc;
    /* CBC, CTR and ECB are provided by crypto engine */
    crypto_driver->aes_cbc_mac_enc_raw = aes_cbc_mac_board_enc_raw; 
    crypto_driver->aes_ctr_enc = aes_ctr_board_enc;
    crypto_driver->aes_ctr_enc_raw = aes_ctr_board_enc_raw;
    crypto_driver->aes_ecb_enc = aes_ecb_board_enc;

    return 0;
}
```

Software implementations were provided for all functions except for aes_ecb_enc where a 
TI code was used (it should work on 8/16 bits processors, see aes_ecb.c). 
It is possible to use openssl implementation for aes_ecb_enc if you are using a 32 bits processor (see aes_core.c). 

Hardware implementations were simulated using openssl. They should be replaced by crypto processor calls.

Author: Marcelo Barros
