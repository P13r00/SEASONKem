
# Consider dependencies only in project.
set(CMAKE_DEPENDS_IN_PROJECT_ONLY OFF)

# The set of languages for which implicit dependencies are needed:
set(CMAKE_DEPENDS_LANGUAGES
  "ASM"
  )
# The set of files for implicit dependencies of each language:
set(CMAKE_DEPENDS_CHECK_ASM
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/lwc-finalists/src/combined/internal-ascon-armv7m.S" "/home/piec/Documents/ResearchInternship/cryptoBenchmark/build/CMakeFiles/stm32_benchmark.elf.dir/third_party/lwc-finalists/src/combined/internal-ascon-armv7m.S.obj"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/lwc-finalists/src/combined/internal-sparkle-armv7m.S" "/home/piec/Documents/ResearchInternship/cryptoBenchmark/build/CMakeFiles/stm32_benchmark.elf.dir/third_party/lwc-finalists/src/combined/internal-sparkle-armv7m.S.obj"
  )
set(CMAKE_ASM_COMPILER_ID "GNU")

# Preprocessor definitions for this target.
set(CMAKE_TARGET_DEFINITIONS_ASM
  "COMPILE_CHACHA20_POLY1305=0"
  "COMPILE_FLEXWING0=0"
  "COMPILE_FLEXWING1=0"
  "COMPILE_FLEXWING2=0"
  "COMPILE_FLEXWING3=0"
  "COMPILE_FLEXWING4=0"
  "COMPILE_LWC_ASCON128_AEAD=1"
  "COMPILE_LWC_ASCON80PQ_AEAD=1"
  "COMPILE_LWC_ASCON_HASH256=1"
  "COMPILE_LWC_ASCON_HASHXOF=1"
  "COMPILE_LWC_SPARKLE_AEAD128=1"
  "COMPILE_LWC_SPARKLE_AEAD192=1"
  "COMPILE_LWC_SPARKLE_AEAD256=0"
  "COMPILE_LWC_SPARKLE_HASH256=0"
  "COMPILE_LWC_SPARKLE_HASH384=0"
  "COMPILE_LWC_SPARKLE_HASHXOF=0"
  "COMPILE_LWC_XOODYAK_AEAD=0"
  "COMPILE_LWC_XOODYAK_HASH=0"
  "COMPILE_PQM4_DILITHIUM2=0"
  "COMPILE_PQM4_FALCON512=0"
  "COMPILE_PQM4_KYBER512=0"
  "COMPILE_PQM4_KYBER768=0"
  "COMPILE_PQM4_SHA3_256=0"
  "COMPILE_PQM4_SHAKE256=0"
  "COMPILE_X25519=0"
  "COMPILE_XWING=0"
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
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/X25519-Cortex-M4"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/wolfssl"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/adapters/wolf"
  )

# The set of dependency files which are needed:
set(CMAKE_DEPENDS_DEPENDENCY_FILES
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/adapters/adapter_rng.c" "CMakeFiles/stm32_benchmark.elf.dir/adapters/adapter_rng.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/adapters/adapter_rng.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/adapters/lwc/crypto_lwc_ascon128_aead.c" "CMakeFiles/stm32_benchmark.elf.dir/adapters/lwc/crypto_lwc_ascon128_aead.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/adapters/lwc/crypto_lwc_ascon128_aead.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/adapters/lwc/crypto_lwc_ascon80pq_aead.c" "CMakeFiles/stm32_benchmark.elf.dir/adapters/lwc/crypto_lwc_ascon80pq_aead.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/adapters/lwc/crypto_lwc_ascon80pq_aead.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/adapters/lwc/crypto_lwc_ascon_hash256.c" "CMakeFiles/stm32_benchmark.elf.dir/adapters/lwc/crypto_lwc_ascon_hash256.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/adapters/lwc/crypto_lwc_ascon_hash256.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/adapters/lwc/crypto_lwc_ascon_hashxof.c" "CMakeFiles/stm32_benchmark.elf.dir/adapters/lwc/crypto_lwc_ascon_hashxof.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/adapters/lwc/crypto_lwc_ascon_hashxof.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/adapters/lwc/crypto_lwc_sparkle_aead128.c" "CMakeFiles/stm32_benchmark.elf.dir/adapters/lwc/crypto_lwc_sparkle_aead128.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/adapters/lwc/crypto_lwc_sparkle_aead128.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/adapters/lwc/crypto_lwc_sparkle_aead192.c" "CMakeFiles/stm32_benchmark.elf.dir/adapters/lwc/crypto_lwc_sparkle_aead192.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/adapters/lwc/crypto_lwc_sparkle_aead192.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/core/src/benchmark_metrics.c" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmark_metrics.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmark_metrics.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/core/src/benchmark_runner.c" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmark_runner.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmark_runner.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/core/src/benchmarks/bm_aead.c" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_aead.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_aead.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/core/src/benchmarks/bm_hash.c" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_hash.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_hash.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/core/src/benchmarks/bm_kem.c" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_kem.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_kem.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/core/src/benchmarks/bm_kex.c" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_kex.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_kex.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/core/src/benchmarks/bm_signature.c" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_signature.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/core/src/benchmarks/bm_signature.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/platforms/stm32_renode/adapter_rng_seed.c" "CMakeFiles/stm32_benchmark.elf.dir/platforms/stm32_renode/adapter_rng_seed.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/platforms/stm32_renode/adapter_rng_seed.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/platforms/stm32_renode/libc_stub.c" "CMakeFiles/stm32_benchmark.elf.dir/platforms/stm32_renode/libc_stub.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/platforms/stm32_renode/libc_stub.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/platforms/stm32_renode/main.c" "CMakeFiles/stm32_benchmark.elf.dir/platforms/stm32_renode/main.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/platforms/stm32_renode/main.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/platforms/stm32_renode/runtime_overhead_probe.c" "CMakeFiles/stm32_benchmark.elf.dir/platforms/stm32_renode/runtime_overhead_probe.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/platforms/stm32_renode/runtime_overhead_probe.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/lwc-finalists/src/combined/ascon-aead.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/lwc-finalists/src/combined/ascon-aead.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/lwc-finalists/src/combined/ascon-aead.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/lwc-finalists/src/combined/ascon-hash.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/lwc-finalists/src/combined/ascon-hash.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/lwc-finalists/src/combined/ascon-hash.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/lwc-finalists/src/combined/ascon-xof.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/lwc-finalists/src/combined/ascon-xof.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/lwc-finalists/src/combined/ascon-xof.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/lwc-finalists/src/combined/internal-util.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/lwc-finalists/src/combined/internal-util.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/lwc-finalists/src/combined/internal-util.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/lwc-finalists/src/combined/sparkle-aead.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/lwc-finalists/src/combined/sparkle-aead.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/lwc-finalists/src/combined/sparkle-aead.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/wolfssl/wolfcrypt/src/memory.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/memory.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/memory.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/wolfssl/wolfcrypt/src/misc.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/misc.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/misc.c.obj.d"
  "/home/piec/Documents/ResearchInternship/cryptoBenchmark/third_party/wolfssl/wolfcrypt/src/wc_port.c" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/wc_port.c.obj" "gcc" "CMakeFiles/stm32_benchmark.elf.dir/third_party/wolfssl/wolfcrypt/src/wc_port.c.obj.d"
  )

# Targets to which this target links which contain Fortran sources.
set(CMAKE_Fortran_TARGET_LINKED_INFO_FILES
  )

# Targets to which this target links which contain Fortran sources.
set(CMAKE_Fortran_TARGET_FORWARD_LINKED_INFO_FILES
  )

# Fortran module output directory.
set(CMAKE_Fortran_TARGET_MODULE_DIR "")
