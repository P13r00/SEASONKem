#ifndef CRYPTO_API_H
#define CRYPTO_API_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    ALG_CLASSICAL_ECC,      
    ALG_LIGHTWEIGHT_ASCON,   
    ALG_PHOTON_BEETLE,      
    ALG_PQC_SIGN,           
    ALG_PQC_KEM             
} crypto_type_t;

#define CRYPTO_SUCCESS 0
#define CRYPTO_ERROR   -1

// Define the function pointer structural interface
typedef struct {
    crypto_type_t type;
    const char *name;
    int (*sign_keypair)(uint8_t *pk, uint8_t *sk);
    int (*sign)(uint8_t *sig, size_t *siglen, const uint8_t *msg, size_t msglen, const uint8_t *sk);
    int (*verify)(const uint8_t *sig, size_t siglen, const uint8_t *msg, size_t msglen, const uint8_t *pk);
} crypto_ops_t;

// Universal benchmark entry runner
void fill_stack_watermark(void);
void reset_stack_watermark(void);
void execute_signature_benchmark(crypto_type_t type);

#endif // CRYPTO_API_H