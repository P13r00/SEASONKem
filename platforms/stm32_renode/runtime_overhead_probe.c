#ifdef FORCE_RUNTIME_OVERHEAD

extern void *malloc(unsigned int);
extern int   custom_rand_generate_seed(unsigned char *output, unsigned int sz);

__attribute__((used, section(".keep_alive")))
static void *(*const keep_alive[])(void) = {
    (void *)malloc,
    (void *)custom_rand_generate_seed,
};

#endif