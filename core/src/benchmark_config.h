#ifndef BENCHMARK_CONFIG_H
#define BENCHMARK_CONFIG_H

#define RUNS_SIGNATURE                  50
#define COMPILE_WOLF_ED25519            1
#define COMPILE_ECDSAP256               0
#define COMPILE_PQM4_DILITHIUM2         0
#define COMPILE_PQM4_FALCON512          0

#define RUNS_AEAD                       500
#define COMPILE_CHACHA20_POLY1305       0
#define COMPILE_ASCON80                 0
#define COMPILE_ASCON_AEAD128           0
#define COMPILE_AES_GCM                 0
#define COMPILE_LWC_SPARKLE_AEAD256     0
#define COMPILE_LWC_SPARKLE_AEAD192     0
#define COMPILE_LWC_ASCON80PQ_AEAD      0

#define RUNS_KDF                        200
#define COMPILE_HKDF_SHA256             0

#define RUNS_HASH                       50
#define COMPILE_ASCON_HASH256           0
#define COMPILE_PQM4_SHA3_256           0
#define COMPILE_ASCON_XOF               0
#define COMPILE_PQM4_SHAKE256           0
#define COMPILE_LWC_SPARKLE_HASHXOF     0
#define COMPILE_LWC_SPARKLE_HASH256     0
#define COMPILE_LWC_XOODYAK_HASH        0

#define RUNS_KEM                        20
#define COMPILE_PQM4_KYBER512           0
#define COMPILE_PQM4_KYBER768           0

#define RUNS_KEX                        50
#define COMPILE_WOLF_X25519             1

#define HASH_BUFFER_SIZE                96u

#endif // BENCHMARK_CONFIG_H