#ifndef BENCHMARK_CONFIG_H
#define BENCHMARK_CONFIG_H

// Algorithm Selection Switches (1 = Enabled, 0 = Disabled)
#define COMPILE_WOLF_ED25519            0
#define COMPILE_ECDSAP256               0
#define COMPILE_AES_GCM                 0
#define COMPILE_CHACHA20_POLY1305       0
#define COMPILE_HKDF_SHA256             0
#define COMPILE_ASCON80                 0
#define COMPILE_ASCON_AEAD128           0
#define COMPILE_ASCON_HASH256           0
#define COMPILE_ASCON_XOF               1
#define COMPILE_PQM4_KYBER512           0
#define COMPILE_PQM4_KYBER768           0
#define COMPILE_PQM4_DILITHIUM2         0
#define COMPILE_PQM4_FALCON512          0
#define COMPILE_PQM4_SHA3_256           0
#define COMPILE_PQM4_SHAKE256           1
#define COMPILE_WOLF_X25519             0

// --- Independent Iteration Runs ---
#define RUNS_SIGNATURE                  50
#define RUNS_AEAD                       100
#define RUNS_KDF                        200
#define RUNS_HASH                       500
#define RUNS_KEM                        20
#define RUNS_KEX                        50

// --- Configurable Hashing Input Length ---
#define HASH_BUFFER_SIZE                1024u

#endif // BENCHMARK_CONFIG_H