
# Consider dependencies only in project.
set(CMAKE_DEPENDS_IN_PROJECT_ONLY OFF)

# The set of languages for which implicit dependencies are needed:
set(CMAKE_DEPENDS_LANGUAGES
  "ASM"
  )
# The set of files for implicit dependencies of each language:
set(CMAKE_DEPENDS_CHECK_ASM
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/pqm4/common/keccakf1600.S" "/home/piec/Documents/ResearchInternship/cryptoBenchmark/build/CMakeFiles/stm32_benchmark.elf.dir/third_party/pqm4/common/keccakf1600.S.obj"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/ntt.S" "/home/piec/Documents/ResearchInternship/cryptoBenchmark/build/CMakeFiles/stm32_benchmark.elf.dir/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/ntt.S.obj"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/pointwise_mont.s" "/home/piec/Documents/ResearchInternship/cryptoBenchmark/build/CMakeFiles/stm32_benchmark.elf.dir/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/pointwise_mont.s.obj"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/smallntt_769.S" "/home/piec/Documents/ResearchInternship/cryptoBenchmark/build/CMakeFiles/stm32_benchmark.elf.dir/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/smallntt_769.S.obj"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/vector.s" "/home/piec/Documents/ResearchInternship/cryptoBenchmark/build/CMakeFiles/stm32_benchmark.elf.dir/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/vector.s.obj"
  )
set(CMAKE_ASM_COMPILER_ID "GNU")

# Preprocessor definitions for this target.
set(CMAKE_TARGET_DEFINITIONS_ASM
  "COMPILE_AES_GCM=0"
  "COMPILE_ASCON80=0"
  "COMPILE_ASCON_AEAD128=0"
  "COMPILE_ASCON_HASH256=0"
  "COMPILE_ASCON_XOF=0"
  "COMPILE_CHACHA20_POLY1305=0"
  "COMPILE_ECDSAP256=0"
  "COMPILE_HKDF_SHA256=0"
  "COMPILE_LWC_ASCON80PQ_AEAD=0"
  "COMPILE_LWC_SPARKLE_AEAD192=0"
  "COMPILE_LWC_SPARKLE_AEAD256=0"
  "COMPILE_LWC_SPARKLE_HASH256=0"
  "COMPILE_LWC_SPARKLE_HASHXOF=0"
  "COMPILE_LWC_XOODYAK_HASH=0"
  "COMPILE_PQM4_DILITHIUM2=1"
  "COMPILE_PQM4_FALCON512=0"
  "COMPILE_PQM4_KYBER512=0"
  "COMPILE_PQM4_KYBER768=0"
  "COMPILE_PQM4_SHA3_256=0"
  "COMPILE_PQM4_SHAKE256=0"
  "COMPILE_WOLF_ED25519=0"
  "COMPILE_WOLF_X25519=0"
  "RENODE_SIMULATION"
  "WOLFSSL_USER_SETTINGS"
  )

# The include file search paths:
set(CMAKE_ASM_TARGET_INCLUDE_PATH
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/core/src/benchmarks"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/platforms/stm32_renode"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/pqm4/mupq/common"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/pqm4/crypto_sign/ml-dsa-44/m4f"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/pqm4/crypto_sign/fndsa_provisional-512/m4f"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/pqm4"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/wolfssl"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/ascon"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/ascon/tests"
  )

# The set of dependency files which are needed:
set(CMAKE_DEPENDS_DEPENDENCY_FILES
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/adapters/adapter_rng.c" "CMakeFiles/stm32_benchmark.elf.dir/adapters/adapter_rng.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/adapters/adapter_rng.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/adapters/pqm4/crypto_pqm4_dilithium2.c" "CMakeFiles/stm32_benchmark.elf.dir/adapters/pqm4/crypto_pqm4_dilithium2.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/adapters/pqm4/crypto_pqm4_dilithium2.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/core/src/benchmark_metrics.c" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmark_metrics.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmark_metrics.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/core/src/benchmark_runner.c" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmark_runner.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmark_runner.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/core/src/benchmarks/bm_aead.c" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_aead.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_aead.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/core/src/benchmarks/bm_hash.c" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_hash.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_hash.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/core/src/benchmarks/bm_kdf.c" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_kdf.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_kdf.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/core/src/benchmarks/bm_kem.c" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_kem.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_kem.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/core/src/benchmarks/bm_kex.c" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_kex.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_kex.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/core/src/benchmarks/bm_signature.c" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_signature.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_signature.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/platforms/stm32_renode/adapter_rng_seed.c" "CMakeFiles/stm32_benchmark.elf.dir/platforms/stm32_renode/adapter_rng_seed.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/platforms/stm32_renode/adapter_rng_seed.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/platforms/stm32_renode/libc_stub.c" "CMakeFiles/stm32_benchmark.elf.dir/platforms/stm32_renode/libc_stub.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/platforms/stm32_renode/libc_stub.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/platforms/stm32_renode/main.c" "CMakeFiles/stm32_benchmark.elf.dir/platforms/stm32_renode/main.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/platforms/stm32_renode/main.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/packing.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/packing.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/packing.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/poly.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/poly.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/poly.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/polyvec.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/polyvec.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/polyvec.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/rounding.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/rounding.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/rounding.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/sign.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/sign.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/sign.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/smallpoly.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/smallpoly.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/smallpoly.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/symmetric-shake.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/symmetric-shake.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/pqm4/crypto_sign/ml-dsa-44/m4f/symmetric-shake.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/pqm4/mupq/common/fips202.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/pqm4/mupq/common/fips202.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/pqm4/mupq/common/fips202.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/wolfssl/wolfcrypt/src/asn.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/asn.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/asn.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/wolfssl/wolfcrypt/src/hash.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/hash.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/hash.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/wolfssl/wolfcrypt/src/memory.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/memory.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/memory.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/wolfssl/wolfcrypt/src/misc.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/misc.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/misc.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/wolfssl/wolfcrypt/src/random.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/random.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/random.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/wolfssl/wolfcrypt/src/sha256.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/sha256.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/sha256.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/wolfssl/wolfcrypt/src/wc_port.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/wc_port.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/wc_port.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/wolfssl/wolfcrypt/src/wolfmath.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/wolfmath.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/wolfmath.c.obj.d"
  )

# Targets to which this target links which contain Fortran sources.
set(CMAKE_Fortran_TARGET_LINKED_INFO_FILES
  )

# Targets to which this target links which contain Fortran sources.
set(CMAKE_Fortran_TARGET_FORWARD_LINKED_INFO_FILES
  )

# Fortran module output directory.
set(CMAKE_Fortran_TARGET_MODULE_DIR "")
