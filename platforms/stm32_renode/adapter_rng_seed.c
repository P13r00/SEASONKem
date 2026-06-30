#include <stdint.h>

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

int custom_rand_generate_seed(unsigned char *output, unsigned int sz)
{
    if (hw_rng_init() != 0)
        return -1;

    while (sz >= 4u) {
        while (!(*RNG_SR & RNG_SR_DRDY));
        if (*RNG_SR & (RNG_SR_SEIS | RNG_SR_CEIS))
            return -1;
        uint32_t word = *RNG_DR;
        output[0] = (unsigned char)(word);
        output[1] = (unsigned char)(word >> 8);
        output[2] = (unsigned char)(word >> 16);
        output[3] = (unsigned char)(word >> 24);
        output += 4;
        sz -= 4u;
    }
    if (sz > 0u) {
        while (!(*RNG_SR & RNG_SR_DRDY));
        if (*RNG_SR & (RNG_SR_SEIS | RNG_SR_CEIS))
            return -1;
        uint32_t word = *RNG_DR;
        for (unsigned int i = 0; i < sz; i++)
            output[i] = (unsigned char)(word >> (i * 8));
    }
    return 0;
}