
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


int custom_rand_generate_seed(unsigned char *output, unsigned int sz)
{
    return (PQCLEAN_randombytes(output, (size_t)sz) == 0) ? 0 : -1;
}