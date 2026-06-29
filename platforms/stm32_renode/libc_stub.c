/* libc_stub.c
 *
 * Minimal C-library stubs for a -nostdlib freestanding build.
 *
 * Heap model: static bump allocator.
 *   - Allocations are never freed (wc_free is a no-op).
 *   - Total heap is fixed at HEAP_SIZE bytes.
 *   - Sufficient for wolfcrypt: Ed25519 key gen peaks at ~3 KiB;
 *     leave 8 KiB for headroom with WOLFSSL_SMALL_STACK.
 *   - The array lands in .bss, BEFORE _sstack, so it does NOT
 *     interfere with the stack watermark region.
 *
 * In production: replace with a proper allocator (e.g. tlsf) or
 * connect to the STM32F4 SRAM backed by a real heap manager.
 */

#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/*  String / memory primitives                                         */
/* ------------------------------------------------------------------ */

void *memset(void *s, int c, size_t n) {
    unsigned char *p = (unsigned char *)s;
    while (n--) *p++ = (unsigned char)c;
    return s;
}

void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char       *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dst;
}

void *memmove(void *dst, const void *src, size_t n) {
    unsigned char       *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d < s) {
        while (n--) *d++ = *s++;
    } else {
        d += n; s += n;
        while (n--) *--d = *--s;
    }
    return dst;
}

int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *p = (const unsigned char *)a;
    const unsigned char *q = (const unsigned char *)b;
    while (n--) {
        if (*p != *q) return (int)*p - (int)*q;
        p++; q++;
    }
    return 0;
}

size_t strlen(const char *s) {
    size_t n = 0;
    while (*s++) n++;
    return n;
}

/* ------------------------------------------------------------------ */
/*  Heap — static bump allocator                                       */
/* ------------------------------------------------------------------ */

#define HEAP_SIZE (8u * 1024u)          /* 8 KiB — adjust if you add  */
                                         /* more algorithms or larger   */
                                         /* key sizes (e.g. RSA-2048)  */

static uint8_t s_heap[HEAP_SIZE];       /* lives in .bss              */
static size_t  s_heap_top = 0;

void *malloc(size_t n) {
    /* 8-byte align for double / uint64_t fields inside wolfcrypt structs */
    n = (n + 7u) & ~7u;
    if (s_heap_top + n > HEAP_SIZE) return NULL;   /* OOM */
    void *p = &s_heap[s_heap_top];
    s_heap_top += n;
    return p;
}

void free(void *p) {
    (void)p;    /* bump allocator: frees are no-ops */
}

void *realloc(void *p, size_t n) {
    /* Naive: allocate fresh, copy up to n bytes.
     * Safe here because wolfcrypt only reallocs to grow a buffer,
     * and bump-allocated blocks are never freed anyway. */
    void *q = malloc(n);
    if (q && p) memcpy(q, p, n);   /* may over-read old block; acceptable */
    return q;
}

void *calloc(size_t count, size_t size) {
    void *p = malloc(count * size);
    if (p) memset(p, 0, count * size);
    return p;
}

/* ------------------------------------------------------------------ */
/*  Abort / assert                                                     */
/* ------------------------------------------------------------------ */

void abort(void) {
    while (1);  /* trap — attach debugger or watch via Renode monitor */
}

/* GCC internal assert used by some wolfSSL debug paths */
void __assert_func(const char *f, int l, const char *fn, const char *e) {
    (void)f; (void)l; (void)fn; (void)e;
    while (1);
}