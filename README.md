ccms
====

CCM* implementation for 802.15.4e 2012 networks

AES-128 is implemented using openssl routines.

| Level(*) | Description |
|----------|-------------|
| 0 | No security coprocessor available. AES-128 and other functions are executed by firmware |
| 1 | Security coprocessor is present but only AES-128 cipher is available (ECB) |
| 2 | CBC is available, besides all modes in level 1 |
| 3 | CTR is available, besides all modes in level 2 |
| 4 | CCM-MAC is available, besides all modes in level 3 |
| 5 | CCM* is available, besides all modes in level 4
(*) Hardware Encryption Level
