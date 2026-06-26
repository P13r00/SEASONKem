/* pqm4_randombytes.c — single PQCLEAN_randombytes() provider for all pqm4 algorithms.
 *
 * pqm4's randombytes.h does:
 *   #define randombytes  PQCLEAN_randombytes
 *   int randombytes(uint8_t *output, size_t n);
 *
 * So every call site inside pqm4 compiles to PQCLEAN_randombytes().
 * We must define that symbol here with the matching int return type.
 *
 * Do NOT include the pqm4 randombytes.h here — the macro would rename
 * our own definition and cause a recursive / mismatched symbol.
 *
 * This file must be compiled exactly once (CMakeLists adds it when
 * COMPILE_KYBER512 OR COMPILE_DILITHIUM2 is set).
 */

#include <stdint.h>
#include <stddef.h>
#include <wolfssl/wolfcrypt/random.h>

static WC_RNG s_pqm4_rng;
static int    s_pqm4_rng_ready = 0;

int PQCLEAN_randombytes(uint8_t *out, size_t outlen) {
    if (!s_pqm4_rng_ready) {
        if (wc_InitRng(&s_pqm4_rng) != 0) return -1;
        s_pqm4_rng_ready = 1;
    }
    if (wc_RNG_GenerateBlock(&s_pqm4_rng, out, (word32)outlen) != 0) return -1;
    return 0;
}