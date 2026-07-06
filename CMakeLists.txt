cmake_minimum_required(VERSION 3.15)

if(TARGET_PLATFORM STREQUAL "STM32")
    set(CMAKE_SYSTEM_NAME Generic)
    set(CMAKE_SYSTEM_PROCESSOR arm)

    set(CMAKE_C_COMPILER   arm-none-eabi-gcc)
    set(CMAKE_ASM_COMPILER arm-none-eabi-gcc)
    set(CMAKE_OBJCOPY      arm-none-eabi-objcopy)
    set(CMAKE_SIZE         arm-none-eabi-size)

    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
endif()

project(crypto_heterogeneous_benchmark C ASM)

set(CMAKE_C_STANDARD 99)

# ---------------------------------------------------------------------------
# Master algorithm list — single source of truth, used both for parsing
# benchmark_config.h defaults and for ISOLATE_ALGO override below.
# ---------------------------------------------------------------------------
set(ALGO_LIST
    WOLF_ED25519 AES_GCM CHACHA20_POLY1305 HKDF_SHA256 ECDSAP256
    ASCON80 ASCON_AEAD128 ASCON_HASH256 ASCON_XOF
    PQM4_KYBER512 PQM4_KYBER768 PQM4_DILITHIUM2 PQM4_FALCON512
    WOLF_X25519 PQM4_SHA3_256 PQM4_SHAKE256
    LWC_SPARKLE_AEAD256 LWC_SPARKLE_AEAD192 LWC_SPARKLE_HASHXOF
    LWC_SPARKLE_HASH256 LWC_XOODYAK_HASH LWC_ASCON80PQ_AEAD
)

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/core/src/benchmark_config.h" RUNNER_CONTENT)

foreach(ALG ${ALGO_LIST})
    if(RUNNER_CONTENT MATCHES "#define[ \t]+COMPILE_${ALG}[ \t]+1")
        set(COMPILE_${ALG} 1)
    else()
        set(COMPILE_${ALG} 0)
    endif()
endforeach()

# ---------------------------------------------------------------------------
# ISOLATE_ALGO override: when set, forces exactly one algorithm (or none) on,
# regardless of what benchmark_config.h has enabled. Used to produce clean
# single-algorithm binaries for accurate per-algorithm Flash/BSS measurement.
#
# Usage:
#   cmake -DTARGET_PLATFORM=STM32 -DISOLATE_ALGO=LWC_XOODYAK_HASH ..
#   cmake -DTARGET_PLATFORM=STM32 -DISOLATE_ALGO=__NONE__ ..   (baseline, no algo)
#   cmake -DTARGET_PLATFORM=STM32 ..                            (normal combined build)
# ---------------------------------------------------------------------------
if(DEFINED ISOLATE_ALGO AND NOT ISOLATE_ALGO STREQUAL "")
    list(FIND ALGO_LIST "${ISOLATE_ALGO}" _isolate_index)
    if(_isolate_index EQUAL -1 AND NOT ISOLATE_ALGO STREQUAL "__NONE__")
        message(FATAL_ERROR "ISOLATE_ALGO='${ISOLATE_ALGO}' is not a recognized algorithm. "
                             "Valid values: __NONE__, ${ALGO_LIST}")
    endif()

    foreach(ALG ${ALGO_LIST})
        if(ALG STREQUAL ISOLATE_ALGO)
            set(COMPILE_${ALG} 1)
        else()
            set(COMPILE_${ALG} 0)
        endif()
    endforeach()

    message(STATUS "ISOLATE_ALGO active: only COMPILE_${ISOLATE_ALGO} is enabled "
                    "(use __NONE__ for the zero-algorithm baseline build)")
endif()

set(CORE_SOURCES
    core/src/benchmark_runner.c
    core/src/benchmark_metrics.c
    core/src/benchmarks/bm_aead.c
    core/src/benchmarks/bm_hash.c
    core/src/benchmarks/bm_kdf.c
    core/src/benchmarks/bm_kem.c
    core/src/benchmarks/bm_kex.c
    core/src/benchmarks/bm_signature.c
)

set(WOLFCRYPT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/wolfssl)
set(WOLFCRYPT_SOURCES "")
set(WOLFCRYPT_INCLUDES
    ${WOLFCRYPT_DIR}
)

set(WOLFCRYPT_RNG 1)

if(WOLFCRYPT_RNG)
    list(APPEND WOLFCRYPT_SOURCES
        ${WOLFCRYPT_DIR}/wolfcrypt/src/wc_port.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/memory.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/wolfmath.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/misc.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/asn.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/random.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/hash.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/sha256.c
        adapters/adapter_rng.c
    )
endif()

if(COMPILE_HKDF_SHA256)
    list(APPEND WOLFCRYPT_SOURCES
        ${WOLFCRYPT_DIR}/wolfcrypt/src/hmac.c
    )
    list(APPEND CORE_SOURCES "adapters/wolf/crypto_hkdfsha256.c")
endif()

if(COMPILE_WOLF_ED25519)
    list(APPEND WOLFCRYPT_SOURCES
        ${WOLFCRYPT_DIR}/wolfcrypt/src/sha512.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/ed25519.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/ge_operations.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/fe_operations.c
    )
    list(APPEND CORE_SOURCES "adapters/wolf/crypto_wolf_ed25519.c")
endif()

if(COMPILE_ECDSAP256)
    list(APPEND WOLFCRYPT_SOURCES
        ${WOLFCRYPT_DIR}/wolfcrypt/src/ecc.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/sp_int.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/sp_c32.c
    )
    list(APPEND CORE_SOURCES "adapters/wolf/crypto_ecdsap256.c")
endif()

if(COMPILE_AES_GCM)
    list(APPEND WOLFCRYPT_SOURCES
        ${WOLFCRYPT_DIR}/wolfcrypt/src/aes.c
    )
    list(APPEND CORE_SOURCES "adapters/wolf/crypto_aes_gcm.c")
endif()

if(COMPILE_CHACHA20_POLY1305)
    list(APPEND WOLFCRYPT_SOURCES
        ${WOLFCRYPT_DIR}/wolfcrypt/src/chacha.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/poly1305.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/chacha20_poly1305.c
    )
    list(APPEND CORE_SOURCES "adapters/wolf/crypto_chacha20_poly1305.c")
endif()

if(COMPILE_WOLF_X25519)
    list(APPEND WOLFCRYPT_SOURCES
        ${WOLFCRYPT_DIR}/wolfcrypt/src/curve25519.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/fe_operations.c
    )
    list(APPEND CORE_SOURCES "adapters/wolf/crypto_wolf_x25519.c")
endif()

list(REMOVE_DUPLICATES WOLFCRYPT_SOURCES)

set(ASCON_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ascon)
set(ASCON_SOURCES "")
set(ASCON_INCLUDES
    ${ASCON_DIR}
    ${ASCON_DIR}/tests
)

if(COMPILE_ASCON80)
    list(APPEND ASCON_SOURCES
        ${ASCON_DIR}/crypto_aead/ascon80pqv12/armv7m/aead.c
        ${ASCON_DIR}/crypto_aead/ascon80pqv12/armv7m/permutations.c
    )
    list(APPEND CORE_SOURCES "adapters/ascon/crypto_ascon80pq.c")
endif()

if(COMPILE_ASCON_AEAD128)
    list(APPEND ASCON_SOURCES
        ${ASCON_DIR}/crypto_aead/ascon128abi32v12/bi32_armv7m/aead.c
        ${ASCON_DIR}/crypto_aead/ascon128abi32v12/bi32_armv7m/permutations.c
    )
    list(APPEND CORE_SOURCES "adapters/ascon/crypto_asconaead128.c")
endif()

if(COMPILE_ASCON_HASH256)
    list(APPEND ASCON_SOURCES
        ${ASCON_DIR}/crypto_hash/asconhashav12/bi32_armv7m_small/hash.c
        ${ASCON_DIR}/crypto_hash/asconhashav12/bi32_armv7m_small/permutations.c
        ${ASCON_DIR}/crypto_hash/asconhashav12/bi32_armv7m_small/interleave.c
        ${ASCON_DIR}/crypto_hash/asconhashav12/bi32_armv7m_small/constants.c
    )
    list(APPEND CORE_SOURCES "adapters/ascon/crypto_asconhash256.c")
endif()

if(COMPILE_ASCON_XOF)
    list(APPEND ASCON_SOURCES
        ${ASCON_DIR}/crypto_hash/asconxofav12/bi32_armv7m_small/hash.c
        ${ASCON_DIR}/crypto_hash/asconxofav12/bi32_armv7m_small/permutations.c
        ${ASCON_DIR}/crypto_hash/asconxofav12/bi32_armv7m_small/interleave.c
        ${ASCON_DIR}/crypto_hash/asconxofav12/bi32_armv7m_small/constants.c
    )
    list(APPEND CORE_SOURCES "adapters/ascon/crypto_asconxof.c")
endif()

set(PQM4_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/pqm4)
set(PQM4_SOURCES "")
set(PQM4_INCLUDES
    ${PQM4_DIR}/mupq/common
    ${PQM4_DIR}/crypto_sign/ml-dsa-44/m4f
    ${PQM4_DIR}/crypto_sign/fndsa_provisional-512/m4f
    ${PQM4_DIR}
)

if(COMPILE_PQM4_KYBER512)
    file(GLOB PQM4_KEM_SOURCES
        "${PQM4_DIR}/crypto_kem/ml-kem-512/m4fspeed/*.c"
        "${PQM4_DIR}/crypto_kem/ml-kem-512/m4fspeed/*.S"
        "${PQM4_DIR}/crypto_kem/ml-kem-512/m4fspeed/*.s"
    )
    list(APPEND PQM4_SOURCES
        ${PQM4_KEM_SOURCES}
        ${PQM4_DIR}/mupq/common/fips202.c
        ${PQM4_DIR}/common/keccakf1600.S
    )
    list(APPEND CORE_SOURCES "adapters/pqm4/crypto_pqm4_kyber512.c")
endif()

if(COMPILE_PQM4_KYBER768)
    file(GLOB PQM4_KEM_SOURCES
        "${PQM4_DIR}/crypto_kem/ml-kem-768/m4fspeed/*.c"
        "${PQM4_DIR}/crypto_kem/ml-kem-768/m4fspeed/*.S"
        "${PQM4_DIR}/crypto_kem/ml-kem-768/m4fspeed/*.s"
    )
    list(APPEND PQM4_SOURCES
        ${PQM4_KEM_SOURCES}
        ${PQM4_DIR}/mupq/common/fips202.c
        ${PQM4_DIR}/common/keccakf1600.S
    )
    list(APPEND CORE_SOURCES "adapters/pqm4/crypto_pqm4_kyber768.c")
endif()

if(COMPILE_PQM4_DILITHIUM2)
    file(GLOB PQM4_SIGN_M4F_SOURCES
        "${PQM4_DIR}/crypto_sign/ml-dsa-44/m4f/*.c"
        "${PQM4_DIR}/crypto_sign/ml-dsa-44/m4f/*.S"
        "${PQM4_DIR}/crypto_sign/ml-dsa-44/m4f/*.s"
    )
    list(APPEND PQM4_SOURCES
        ${PQM4_SIGN_M4F_SOURCES}
        ${PQM4_DIR}/mupq/common/fips202.c
        ${PQM4_DIR}/common/keccakf1600.S
    )
    list(APPEND CORE_SOURCES "adapters/pqm4/crypto_pqm4_dilithium2.c")
endif()

if(COMPILE_PQM4_FALCON512)
    file(GLOB PQM4_FALCON_SOURCES
        "${PQM4_DIR}/crypto_sign/fndsa_provisional-512/m4f/*.c"
        "${PQM4_DIR}/crypto_sign/fndsa_provisional-512/m4f/*.s"
        "${PQM4_DIR}/crypto_sign/fndsa_provisional-512/m4f/*.S"
    )
    list(APPEND PQM4_SOURCES ${PQM4_FALCON_SOURCES})
    list(APPEND CORE_SOURCES "adapters/pqm4/crypto_pqm4_falcon512.c")
endif()

if(COMPILE_PQM4_SHA3_256)
    list(APPEND PQM4_SOURCES
        ${PQM4_DIR}/mupq/common/fips202.c
        ${PQM4_DIR}/common/keccakf1600.S
    )
    list(APPEND CORE_SOURCES "adapters/pqm4/crypto_pqm4_sha3_256.c")
endif()

if(COMPILE_PQM4_SHAKE256)
    list(APPEND PQM4_SOURCES
        ${PQM4_DIR}/mupq/common/fips202.c
        ${PQM4_DIR}/common/keccakf1600.S
    )
    list(APPEND CORE_SOURCES "adapters/pqm4/crypto_pqm4_shake256.c")
endif()

if(PQM4_SOURCES)
    list(REMOVE_DUPLICATES PQM4_SOURCES)
endif()


set(LWC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lwc-finalists)
set(LWC_SOURCES "")
set(LWC_INCLUDES
)

if(COMPILE_LWC_SPARKLE_AEAD256)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/src/combined/sparkle-aead.c
        ${LWC_DIR}/src/combined/internal-sparkle-armv7m.S
        ${LWC_DIR}/src/combined/internal-util.c
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_sparkle_aead256.c")
endif()

if(COMPILE_LWC_SPARKLE_AEAD192)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/src/combined/sparkle-aead.c
        ${LWC_DIR}/src/combined/internal-sparkle-armv7m.S
        ${LWC_DIR}/src/combined/internal-util.c
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_sparkle_aead192.c")
endif()

if(COMPILE_LWC_ASCON80PQ_AEAD)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/src/combined/ascon-aead.c
        ${LWC_DIR}/src/combined/internal-ascon-armv7m.S
        ${LWC_DIR}/src/combined/internal-util.c
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_ascon80pq_aead.c")
endif()

if(COMPILE_LWC_SPARKLE_HASHXOF)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/src/combined/sparkle-hash.c
        ${LWC_DIR}/src/combined/internal-sparkle-armv7m.S
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_sparkle_hashxof.c")
endif()

if(COMPILE_LWC_SPARKLE_HASH256)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_sparkle_hash256.c")
endif()

if(COMPILE_LWC_XOODYAK_HASH)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/src/combined/xoodyak-hash.c
        ${LWC_DIR}/src/combined/internal-xoodoo-armv7m.S
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_xoodyak.c")
endif()

if(LWC_SOURCES)
    list(REMOVE_DUPLICATES LWC_SOURCES)
endif()

if(TARGET_PLATFORM STREQUAL "STM32")

    set(ARM_MCU_FLAGS
        -mcpu=cortex-m4
        -mthumb
        -mfloat-abi=hard
        -mfpu=fpv4-sp-d16
    )

    set(PLATFORM_SOURCES
        platforms/stm32_renode/main.c
        platforms/stm32_renode/libc_stub.c
        platforms/stm32_renode/adapter_rng_seed.c
        ${REGISTERED_ADAPTER_SOURCES}
        ${WOLFCRYPT_SOURCES}
        ${ASCON_SOURCES}
        ${PQM4_SOURCES}
        ${LWC_SOURCES}
    )

    set(LINKER_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/platforms/stm32_renode/linker.ld")

    add_executable(stm32_benchmark.elf ${CORE_SOURCES} ${PLATFORM_SOURCES})

    target_compile_definitions(stm32_benchmark.elf PRIVATE
        WOLFSSL_USER_SETTINGS
        RENODE_SIMULATION
    )

    # Force the compiled-in COMPILE_<ALG> values (whether they came from
    # benchmark_config.h defaults or from an ISOLATE_ALGO override) to match
    # exactly what CMake decided above. Without this, the #if COMPILE_X guards
    # inside bm_*.c / adapter headers would still see benchmark_config.h's
    # original values via #include, which defeats ISOLATE_ALGO entirely.
    # This requires each COMPILE_* macro in benchmark_config.h to be wrapped
    # in #ifndef / #endif so a command-line -D definition can override it:
    #
    #   #ifndef COMPILE_WOLF_ED25519
    #   #define COMPILE_WOLF_ED25519 1
    #   #endif
    #
    foreach(ALG ${ALGO_LIST})
        target_compile_definitions(stm32_benchmark.elf PRIVATE COMPILE_${ALG}=${COMPILE_${ALG}})
    endforeach()

    target_compile_options(stm32_benchmark.elf PRIVATE
        ${ARM_MCU_FLAGS}
        -ffreestanding
        -O3
        -ffunction-sections
        -fdata-sections
    )

    target_include_directories(stm32_benchmark.elf PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/core/src/benchmarks
        ${CMAKE_CURRENT_SOURCE_DIR}/platforms/stm32_renode
        ${PQM4_INCLUDES}
        ${WOLFCRYPT_INCLUDES}
        ${ASCON_INCLUDES}
    )

    target_link_options(stm32_benchmark.elf PRIVATE
        ${ARM_MCU_FLAGS}
        -T ${LINKER_SCRIPT}
        -nodefaultlibs
        -nostartfiles
        -Wl,--gc-sections
    )
    target_link_libraries(stm32_benchmark.elf PRIVATE gcc)

    add_custom_command(TARGET stm32_benchmark.elf POST_BUILD
        COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:stm32_benchmark.elf> ${CMAKE_PROJECT_NAME}.bin
        COMMAND ${CMAKE_OBJCOPY} -O ihex   $<TARGET_FILE:stm32_benchmark.elf> ${CMAKE_PROJECT_NAME}.hex
        COMMAND ${CMAKE_SIZE} $<TARGET_FILE:stm32_benchmark.elf>
    )

elseif(TARGET_PLATFORM STREQUAL "RP2040")
    # Placeholder
endif()