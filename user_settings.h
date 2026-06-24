/* user_settings.h — bare-metal wolfcrypt config for STM32F4 / Renode */
#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

/* ---- Scope -------------------------------------------------------- */
/* Strip TLS/SSL; keep only the crypto library */
#define WOLFCRYPT_ONLY

/* ---- Bare-metal constraints --------------------------------------- */
#define NO_FILESYSTEM
#define NO_WOLFSSL_DIR
#define WOLFSSL_NO_SOCK
#define NO_WRITEV
#define NO_STDIO_FILESYSTEM
#define SINGLE_THREADED
#define WC_NO_ASYNC_THREADING
#define NO_WOLFSSL_MEMORY       /* disable wolfSSL's own alloc tracking */
#define WOLFSSL_GENSEED_FORTEST

/* ---- Algorithms --------------------------------------------------- */
#define HAVE_ED25519            /* Ed25519 sign / verify                */
#define HAVE_CURVE25519         /* Ed25519 depends on this internally   */
#define HAVE_AESGCM             /* AES-128-GCM encrypt / decrypt        */
#define HAVE_CHACHA             /* ChaCha20 stream cipher               */
#define HAVE_POLY1305           /* Poly1305 MAC                         */
#define HAVE_HKDF               /* HKDF-SHA-256 extract + expand        */


/* ---- Disable unused algorithms (saves ~60–100 KiB flash) ---------- */
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
#define NO_ERROR_STRINGS        /* removes human-readable error table   */
#define WOLFSSL_SHA512

/* ---- Side-channel hardening --------------------------------------- */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* ---- Stack reduction --------------------------------------------- */
/*
 * WOLFSSL_SMALL_STACK moves large local arrays to XMALLOC (heap) rather
 * than the call stack.  This shrinks peak stack HWM but increases heap
 * traffic.  For a fair stack benchmark, comment this out; for fitting
 * within 128 KiB RAM without stack overflows, keep it in.
 */

/* ---- Memory ------------------------------------------------------- */
/*
 * wolfSSL's default XMALLOC/XFREE macros expand to malloc/free.
 * We provide those in platforms/stm32_renode/libc_stub.c as a bump
 * allocator backed by a static array, so no macro override is needed.
 * The linker will satisfy the undefined references from that TU.
 */

#endif /* WOLFSSL_USER_SETTINGS_H */