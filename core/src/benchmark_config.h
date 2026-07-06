#ifndef BENCHMARK_CONFIG_H
#define BENCHMARK_CONFIG_H

#define RUNS_SIGNATURE                  50
#ifndef COMPILE_WOLF_ED25519
#define COMPILE_WOLF_ED25519            0
#endif
#ifndef COMPILE_ECDSAP256
#define COMPILE_ECDSAP256               0
#endif
#ifndef COMPILE_PQM4_DILITHIUM2
#define COMPILE_PQM4_DILITHIUM2         0
#endif
#ifndef COMPILE_PQM4_FALCON512
#define COMPILE_PQM4_FALCON512          0
#endif

#define RUNS_AEAD                       500
#ifndef COMPILE_CHACHA20_POLY1305
#define COMPILE_CHACHA20_POLY1305       0
#endif
#ifndef COMPILE_ASCON80
#define COMPILE_ASCON80                 1
#endif
#ifndef COMPILE_ASCON_AEAD128
#define COMPILE_ASCON_AEAD128           0
#endif
#ifndef COMPILE_AES_GCM
#define COMPILE_AES_GCM                 0
#endif
#ifndef COMPILE_LWC_SPARKLE_AEAD256
#define COMPILE_LWC_SPARKLE_AEAD256     0
#endif
#ifndef COMPILE_LWC_SPARKLE_AEAD192
#define COMPILE_LWC_SPARKLE_AEAD192     0
#endif
#ifndef COMPILE_LWC_ASCON80PQ_AEAD
#define COMPILE_LWC_ASCON80PQ_AEAD      0
#endif

#define RUNS_KDF                        200
#ifndef COMPILE_HKDF_SHA256
#define COMPILE_HKDF_SHA256             0
#endif

#define RUNS_HASH                       50
#ifndef COMPILE_ASCON_HASH256
#define COMPILE_ASCON_HASH256           0
#endif
#ifndef COMPILE_PQM4_SHA3_256
#define COMPILE_PQM4_SHA3_256           0
#endif
#ifndef COMPILE_ASCON_XOF
#define COMPILE_ASCON_XOF               0
#endif
#ifndef COMPILE_PQM4_SHAKE256
#define COMPILE_PQM4_SHAKE256           0
#endif
#ifndef COMPILE_LWC_SPARKLE_HASHXOF
#define COMPILE_LWC_SPARKLE_HASHXOF     0
#endif
#ifndef COMPILE_LWC_SPARKLE_HASH256
#define COMPILE_LWC_SPARKLE_HASH256     0
#endif
#ifndef COMPILE_LWC_XOODYAK_HASH
#define COMPILE_LWC_XOODYAK_HASH        0
#endif

#define RUNS_KEM                        20
#ifndef COMPILE_PQM4_KYBER512
#define COMPILE_PQM4_KYBER512           0
#endif
#ifndef COMPILE_PQM4_KYBER768
#define COMPILE_PQM4_KYBER768           0
#endif

#define RUNS_KEX                        50
#ifndef COMPILE_WOLF_X25519
#define COMPILE_WOLF_X25519             0
#endif

#define HASH_BUFFER_SIZE                96u

#endif // BENCHMARK_CONFIG_H