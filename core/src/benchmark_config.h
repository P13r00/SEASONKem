#ifndef BENCHMARK_CONFIG_H
#define BENCHMARK_CONFIG_H

#define RUNS_SIGNATURE                  50
#ifndef COMPILE_WOLF_ED25519
#define COMPILE_WOLF_ED25519            0
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
#ifndef COMPILE_LWC_SPARKLE_AEAD256
#define COMPILE_LWC_SPARKLE_AEAD256     0
#endif
#ifndef COMPILE_LWC_SPARKLE_AEAD192
#define COMPILE_LWC_SPARKLE_AEAD192     1
#endif
#ifndef COMPILE_LWC_SPARKLE_AEAD128
#define COMPILE_LWC_SPARKLE_AEAD128     1
#endif
#ifndef COMPILE_LWC_ASCON80PQ_AEAD
#define COMPILE_LWC_ASCON80PQ_AEAD      0
#endif
#ifndef COMPILE_LWC_ASCON128_AEAD
#define COMPILE_LWC_ASCON128_AEAD       1
#endif
#ifndef COMPILE_LWC_XOODYAK_AEAD
#define COMPILE_LWC_XOODYAK_AEAD        0
#endif

#define RUNS_HASH                       50
#ifndef COMPILE_ASCON_HASH256
#define COMPILE_ASCON_HASH256           0
#endif
#ifndef COMPILE_PQM4_SHA3_256
#define COMPILE_PQM4_SHA3_256           0
#endif
#ifndef COMPILE_PQM4_SHAKE256
#define COMPILE_PQM4_SHAKE256           0
#endif
#ifndef COMPILE_LWC_SPARKLE_HASHXOF
#define COMPILE_LWC_SPARKLE_HASHXOF     1
#endif
#ifndef COMPILE_LWC_SPARKLE_HASH256
#define COMPILE_LWC_SPARKLE_HASH256     1
#endif
#ifndef COMPILE_LWC_SPARKLE_HASH384
#define COMPILE_LWC_SPARKLE_HASH384     1
#endif
#ifndef COMPILE_LWC_XOODYAK_HASH
#define COMPILE_LWC_XOODYAK_HASH        0
#endif
#ifndef COMPILE_LWC_ASCON_HASHXOF
#define COMPILE_LWC_ASCON_HASHXOF       1
#endif
#ifndef COMPILE_LWC_ASCON_HASH256
#define COMPILE_LWC_ASCON_HASH256       1
#endif

#define RUNS_KEM                        100
#ifndef COMPILE_PQM4_KYBER512
#define COMPILE_PQM4_KYBER512           1
#endif
#ifndef COMPILE_PQM4_KYBER768 
#define COMPILE_PQM4_KYBER768           0
#endif
#ifndef COMPILE_XWING                // K768 + X + SHA
#define COMPILE_XWING                   0
#endif
#ifndef COMPILE_FLEXWING0            // K512 + X + SHA
#define COMPILE_FLEXWING0               0
#endif
#ifndef COMPILE_FLEXWING1            // K512 + X + XOODYAK
#define COMPILE_FLEXWING1               0
#endif
#ifndef COMPILE_FLEXWING2            // K512 + X + ASCON XOF
#define COMPILE_FLEXWING2               1
#endif
#ifndef COMPILE_FLEXWING3            // K512 + X + SPARKLE XOF256
#define COMPILE_FLEXWING3               1
#endif
#ifndef COMPILE_FLEXWING4            // K512 + X + SPARKLE 384
#define COMPILE_FLEXWING4               1
#endif

#define RUNS_KEX                        50
#ifndef COMPILE_X25519
#define COMPILE_X25519                  1
#endif

#define HASH_BUFFER_SIZE                135u

#endif // BENCHMARK_CONFIG_H