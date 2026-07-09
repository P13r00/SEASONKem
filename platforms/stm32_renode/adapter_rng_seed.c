/*
 * platforms/stm32_renode/adapter_rng_seed.c
 *
 * SINGLE hardware-facing RNG source for the entire benchmark suite.
 *
 * This file owns the STM32F4 RNG peripheral (RCC_AHB2ENR / RNG_CR / RNG_SR /
 * RNG_DR) directly via register access, rather than depending on libopencm3.
 * pqm4's own common/randombytes.c does the equivalent thing on real
 * hardware (rng_get_random_blocking() via libopencm3, one 32-bit word per
 * DRDY poll); this file reproduces that exact behavior with the register
 * pokes already validated in this project, without pulling libopencm3 into
 * the build.
 *
 * It implements pqm4's own randombytes() contract:
 *
 *     int randombytes(uint8_t *x, size_t xlen);
 *
 * so this becomes the one and only place in the project that reads the RNG
 * peripheral. Every consumer -- wolfSSL (via custom_rand_generate_block in
 * adapters/adapter_rng.c), PQCLEAN_randombytes (pqm4 KEM/signature/hash
 * adapters), and the ASCON / lwc-finalists libraries (which call
 * randombytes() directly per their reference API) -- draws from this same
 * function. There is deliberately no DRBG layer here: each call polls fresh
 * entropy from the peripheral, exactly as pqm4's reference implementation
 * does on real STM32F4 hardware.
 */
#include <stdint.h>
#include <stddef.h>

static volatile uint32_t * const RCC_AHB2ENR = (volatile uint32_t *)0x40023834u;
static volatile uint32_t * const RNG_CR       = (volatile uint32_t *)0x50060800u;
static volatile uint32_t * const RNG_SR       = (volatile uint32_t *)0x50060804u;
static volatile uint32_t * const RNG_DR       = (volatile uint32_t *)0x50060808u;

#define RCC_AHB2ENR_RNGEN   (1u << 6)
#define RNG_CR_RNGEN        (1u << 2)
#define RNG_SR_DRDY         (1u << 0)
#define RNG_SR_SEIS         (1u << 5)
#define RNG_SR_CEIS         (1u << 6)

static int hw_rng_ready = 0;

static int hw_rng_init(void)
{
    if (hw_rng_ready)
        return 0;

    *RCC_AHB2ENR |= RCC_AHB2ENR_RNGEN;
    *RNG_CR      |= RNG_CR_RNGEN;

    while (!(*RNG_SR & RNG_SR_DRDY));

    if (*RNG_SR & (RNG_SR_SEIS | RNG_SR_CEIS))
        return -1;

    hw_rng_ready = 1;
    return 0;
}

/* Poll one fresh 32-bit word straight off the peripheral. No caching, no
 * derivation -- this is the one place that ever reads RNG_DR. */
static int hw_rng_next_word(uint32_t *word_out)
{
    if (hw_rng_init() != 0)
        return -1;

    while (!(*RNG_SR & RNG_SR_DRDY));
    if (*RNG_SR & (RNG_SR_SEIS | RNG_SR_CEIS))
        return -1;

    *word_out = *RNG_DR;
    return 0;
}

/*
 * pqm4 contract: int randombytes(uint8_t *x, size_t xlen);
 * Returns 0 on success, nonzero if the peripheral reports a seed/clock
 * error. This is the canonical, single upstream RNG for the whole project.
 */
int PQCLEAN_randombytes(uint8_t *obuf, size_t len)   /* was: int randombytes(...) */
{
    uint32_t word;

    while (len >= 4u) {
        if (hw_rng_next_word(&word) != 0)
            return -1;
        obuf[0] = (uint8_t)(word);
        obuf[1] = (uint8_t)(word >> 8);
        obuf[2] = (uint8_t)(word >> 16);
        obuf[3] = (uint8_t)(word >> 24);
        obuf += 4;
        len  -= 4u;
    }
    if (len > 0u) {
        if (hw_rng_next_word(&word) != 0)
            return -1;
        for (size_t i = 0; i < len; i++)
            obuf[i] = (uint8_t)(word >> (i * 8));
    }
    return 0;
}



/*
 * Kept for wolfSSL's WOLFSSL_GENSEED_FORTEST hook (wc_GenerateSeed() ->
 * custom_rand_generate_seed()), so wolfSSL's own seeding path draws from
 * the exact same hardware source as everything else in the project rather
 * than a second, parallel entropy path.
 */
int custom_rand_generate_seed(unsigned char *output, unsigned int sz)
{
    return (PQCLEAN_randombytes(output, (size_t)sz) == 0) ? 0 : -1;
}