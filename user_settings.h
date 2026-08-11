/* user_settings.h — bare-metal wolfcrypt config for STM32F4 / Renode */
#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#define WOLFCRYPT_ONLY

#define NO_FILESYSTEM
#define NO_WOLFSSL_DIR
#define WOLFSSL_NO_SOCK
#define NO_INLINE
#define NO_WRITEV
#define NO_STDIO_FILESYSTEM
#define SINGLE_THREADED
#define WC_NO_ASYNC_THREADING
#define NO_WOLFSSL_MEMORY
#define CUSTOM_RAND_GENERATE_SEED custom_rand_generate_seed
int custom_rand_generate_seed(unsigned char* output, unsigned int sz);

#define WOLFSSL_SP_NO_MALLOC 
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_256

#define HAVE_ED25519
#define HAVE_CURVE25519

#undef NO_AES
#define HAVE_AES_CBC
#define HAVE_AESGCM
#define GCM_TABLE_4BIT

#define HAVE_CHACHA
#define HAVE_POLY1305
#define HAVE_HKDF
#define HAVE_ECC
#define HAVE_ECC256
#define HAVE_SHA256
#define WOLFSSL_SHA512

#define NO_SHA
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_MD4
#define NO_MD5
#define NO_RC4
#define NO_DES3
#define NO_PWDBASED
#define NO_OLD_TLS
#define NO_ERROR_STRINGS

#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

#endif /* WOLFSSL_USER_SETTINGS_H */