#ifndef BENCHMARK_CONFIG_H
#define BENCHMARK_CONFIG_H

// Selection point for benchmark
#define COMPILE_WOLF_ED25519            0
#define COMPILE_ECDSAP256               0
#define COMPILE_AES_GCM                 0
#define COMPILE_CHACHA20_POLY1305       0
#define COMPILE_HKDF_SHA256             0
#define COMPILE_ASCON80                 0
#define COMPILE_ASCON_AEAD128           0
#define COMPILE_ASCON_HASH256           0
#define COMPILE_ASCON_XOF               0
#define COMPILE_PQM4_KYBER512           0
#define COMPILE_PQM4_KYBER768           1
#define COMPILE_PQM4_DILITHIUM2         0
#define COMPILE_PQM4_FALCON512          0
#define COMPILE_PQM4_SHA3_256           0
#define COMPILE_PQM4_SHAKE256           0
#define COMPILE_WOLF_X25519             0

#endif // BENCHMARK_CONFIG_H