
#include <stdint.h>
#include <stddef.h>

static volatile uint32_t * const SYST_CVR = (volatile uint32_t *)0xE000E018u;

static uint32_t prng_state = 0;

static void prng_seed_if_needed(void)
{
    if (prng_state != 0)
        return;

        
    uint32_t seed = (*SYST_CVR) ^ (uint32_t)(uintptr_t)&prng_state ^ 0x9E3779B9u;
    prng_state = seed ? seed : 0xDEADBEEFu;
}

static uint32_t xorshift32(void)
{
    uint32_t x = prng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    prng_state = x;
    return x;
}

int PQCLEAN_randombytes(uint8_t *obuf, size_t len)
{
    prng_seed_if_needed();

    uint32_t word;
    while (len >= 4u) {
        word = xorshift32();
        obuf[0] = (uint8_t)(word);
        obuf[1] = (uint8_t)(word >> 8);
        obuf[2] = (uint8_t)(word >> 16);
        obuf[3] = (uint8_t)(word >> 24);
        obuf += 4;
        len  -= 4u;
    }
    if (len > 0u) {
        word = xorshift32();
        for (size_t i = 0; i < len; i++)
            obuf[i] = (uint8_t)(word >> (i * 8));
    }
    return 0;
}

int custom_rand_generate_seed(unsigned char *output, unsigned int sz)
{
    return (PQCLEAN_randombytes(output, (size_t)sz) == 0) ? 0 : -1;
}
