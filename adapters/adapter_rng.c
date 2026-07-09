/*
 * adapters/adapter_rng.c
 *
 * Portable, backend-agnostic RNG middleware. Contains no hardware access
 * of its own -- every function here is a thin call-through to the single
 * canonical randombytes() implementation in
 * platforms/stm32_renode/adapter_rng_seed.c.
 *
 * wolfCrypt has been fully removed from this project, RNG included. There
 * is no WC_RNG type, no wc_InitRng(), and no wolfSSL-specific hook left
 * anywhere in this file. Any future crypto backend -- including the
 * upcoming replacement X25519 adapter (see
 * docs/x25519-adapter-handover.md) -- should get its randomness by calling
 * platform_rng_generate() below (or randombytes() directly), not by
 * expecting an opaque RNG handle type owned by a specific library.
 */
#include <stdint.h>
#include <stddef.h>
#include "randombytes.h"        /* pqm4 contract: int randombytes(uint8_t*, size_t) */
#include "core/inc/crypto_api.h"

/*
 * No global state left to initialize -- the hardware RNG in
 * adapter_rng_seed.c lazily self-initializes the peripheral on its first
 * call. Kept as a stable, explicit entry point for any adapter that wants
 * to eagerly warm up the RNG (e.g. before starting a timed benchmark run so
 * peripheral bring-up doesn't pollute the first measurement).
 */
int platform_rng_init(void)
{
    return CRYPTO_SUCCESS;
}

/* Generic byte-buffer entry point for any backend: ASCON, lwc-finalists,
 * a future X25519 adapter, etc. */
int platform_rng_generate(uint8_t *buf, size_t len)
{
    return (PQCLEAN_randombytes(buf, len) == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR;
}
